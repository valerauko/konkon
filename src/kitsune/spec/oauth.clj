(ns kitsune.spec.oauth
  (:require [clojure.spec.alpha :as s]
            [clojure.string :refer [split]]
            [org.bovinegenius [exploding-fish :as uri]]
            [kitsune.spec.user :as user]))

(s/def ::name string?)
(s/def ::client-name string?)
(s/def ::scopes string?)
(s/def ::scope-coll
  (s/coll-of #{"read" "write" "follow" "push"} :distinct true :min-count 1))

(s/def ::website uri/absolute?)
(s/def ::redirect-uri
  (s/or :default-value #(= % "urn:ietf:wg:oauth:2.0:oob")
        :absolute-uri (s/and uri/absolute?
                             #(empty? (uri/fragment %))
                             #(= (uri/scheme %) "https"))))
(s/def ::uri-coll
  (s/coll-of ::redirect-uri))
(s/def ::redirect-uris string?)

(s/def ::create-app
  (s/keys :req-un [::client-name ::scopes]
          :opt-un [::website ::redirect-uris]))

(s/def ::random-hash
  (s/and string?
         #(-> % count (= 44))))

(s/def ::id int?)
(s/def ::client-id ::random-hash)
(s/def ::secret ::random-hash)
(s/def ::client-secret ::secret)

(s/def ::register-response
  (s/keys :req-un [::id ::client-id ::secret]))

(s/def ::authorization
  (s/and string?
         #(re-matches #"(?:Bearer|Basic) \S+" %)))

(def auth-header-opt
  {:header (s/keys :opt-un [::authorization])})

(def auth-header-req
  {:header (s/keys :req-un [::authorization])})

(defn coerce-scopes
  [input]
  (let [scopes (split (str input) #"\s+")]
    (when (s/valid? ::scope-coll scopes)
      ; need to sort it for certain equality
      (sort scopes))))

(defn coerce-uris
  [raw-input]
  (let [input-array (split (str raw-input) #"\s+")]
    (if (s/valid? ::uri-coll input-array)
      (sort (distinct input-array))))) ; maybe use set?

(s/def ::password ::user/pass)
(s/def ::grant-type #{"authorization-code" "password" "refresh-token"})

(s/def ::state string?)
(def authorize-params
  {:form (s/keys :req-un [::user/email ::password ::client-id]
                 :opt-un [::redirect-uri ::scopes ::state])})

(s/def ::exchange-by-auth
  (s/keys :req-un [::user/email ::password]))

(s/def ::code string?)

(s/def ::exchange-by-code
  (s/keys :req-un [::code]))

(s/def ::exchange-request
  (s/merge (s/or :code ::exchange-by-code
                 :pass ::exchange-by-auth)
           (s/keys :req-un [::grant-type]
                   :opt-un [::client-id ::client-secret])))
