(ns kitsune.routes.core
  (:require [clojure.tools.logging :as log]
            [jsonista.core :as json]
            [reitit.ring :as ring]
            [reitit.ring.spec :as ring-spec]
            [reitit.ring.coercion :as coerce]
            [reitit.coercion.spec :as spec]
            [reitit.swagger :refer [swagger-feature create-swagger-handler]]
            [reitit.swagger-ui :refer [create-swagger-ui-handler]]
            [muuntaja.middleware :refer [wrap-format]]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [ring.middleware.cors :refer [wrap-cors]]
            [muuntaja.core :as muuntaja]
            [muuntaja.format.plain-text :as text-format]
            [reitit.ring.middleware.muuntaja :as m-middleware]
            [camel-snake-kebab.extras :refer [transform-keys]]
            [camel-snake-kebab.core :refer [->kebab-case-keyword
                                            ->snake_case_string]]
            [kitsune.instance :refer [version]]
            [kitsune.routes.user :as user]
            [kitsune.routes.oauth :as oauth]
            [kitsune.routes.webfinger :as webfinger]
            [kitsune.routes.statuses :as statuses]
            [kitsune.routes.instance :as instance]
            [kitsune.routes.relationships :as relationships]))

(def negotiator
  (muuntaja/create
    (-> muuntaja/default-options
        (assoc-in [:formats "application/json" :matches]
                  #"^application/(.+\+)?json$")
    ;    (assoc-in [:formats "application/xml"] (text-format/format))
    ;    (assoc-in [:formats "text/html"] (text-format/format "text/html"))
    )))

(defn sanitize-params
  [params]
  (let [sensitive-keys #{:password :password-confirm}]
    (reduce-kv
      (fn redact [aggr key value]
        (assoc aggr key
               (if (sensitive-keys key)
                 "*redacted*"
                 value)))
      {}
      params)))

(defn wrap-logging
  [handler]
  (fn [{:keys [request-method uri remote-addr]
        {fwd-for :X-Forwarded-For} :headers
        {route :template} :reitit.core/match
        :as request}]
    (let [start (System/nanoTime)
          response (handler request)]
      (log/info (json/write-value-as-string
                  {:status (:status response)
                   :method request-method
                   :path uri
                   :params (sanitize-params (:params request))
                   :route route
                   :remote-addr (or fwd-for remote-addr)
                   :response-time (/ (- (System/nanoTime) start) 1000000.0)}))
      response)))

(defn default-middleware
  [handler]
  (wrap-defaults handler api-defaults))

(defn transform-map
  ([hashmap] (transform-map hashmap ->kebab-case-keyword))
  ([hashmap func]
   (transform-keys
     #(if-not (number? %) (func %) %)
     hashmap)))

(defn case-wrapper
  [handler]
  (fn param-case [request]
    (let [response (-> request
                       (update :body-params transform-map)
                       (update :form-params transform-map)
                       (update :query-params transform-map)
                       handler
                       (update :body #(transform-map % ->snake_case_string)))]
      response)))

(defn cors-wrapper
  [handler]
  (wrap-cors handler :access-control-allow-origin [#"https://pinafore.social"]
                     :access-control-allow-methods [:get :put :post :delete]))

(def router
  (ring/router
    [user/routes
     webfinger/routes
     oauth/routes
     instance/routes
     statuses/routes
     relationships/routes
     ["/swagger.json"
      {:get {:no-doc true
             :middleware ^:replace [] ; the case-wrapper breaks the output
             :swagger {:info {:title "Kitsune API"
                              :description "Very fox microblogging"
                              :version version}
                       :basePath "/"}
             :handler (create-swagger-handler)}}]]
    {:conflicts identity ; mastodon routes conflict all over the place so don't even log
     :validate ring-spec/validate
     :data {:muuntaja negotiator
            :coercion spec/coercion
            :swagger {:id ::api}
            :middleware [wrap-logging
                         cors-wrapper
                         swagger-feature
                         m-middleware/format-middleware
                         case-wrapper
                         coerce/coerce-exceptions-middleware
                         coerce/coerce-request-middleware
                         coerce/coerce-response-middleware]}}))

(def wrapped-handler
  (-> (ring/ring-handler
        router
        (ring/routes
          (create-swagger-ui-handler {:path "/swagger" :jsonEditor true})
          (ring/redirect-trailing-slash-handler)
          (ring/create-default-handler
            {:not-found (constantly {:status 404 :body {:error "Not found"}})})))
      wrap-format
      default-middleware))
