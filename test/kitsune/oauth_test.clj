(ns kitsune.oauth-test
  (:require [clojure.test :refer :all]
            [kitsune.spec.oauth :as spec]
            [kitsune.handlers.oauth :as handlers]))

(deftest app-registration
  (testing "App registration"
    (testing "Scope validation"
      (testing "At least one scope is required"
        (let [coerced (spec/coerce-scopes nil)]
          (is (= coerced nil)))
        (let [coerced (spec/coerce-scopes "")]
          (is (= coerced nil))))
      (testing "If unknown scopes are present, it's treated as invalid"
        (let [coerced (spec/coerce-scopes "read write hoge")]
          (is (= coerced nil)))))
    (testing "Redirect URI validation"
      (testing "Given none or the default, the default is used"
        (let [coerced (spec/coerce-uris nil)]
          (is (= coerced ["urn:ietf:wg:oauth:2.0:oob"]))))
      (testing "All given redirect URIs have to be absolute URIs"
        (let [coerced (spec/coerce-uris "./usr/local/hoge https://example.com")]
          (is (= coerced nil))))
      (testing "Unsafe HTTP redirect URIs are not allowed"
        (let [coerced (spec/coerce-uris "http://example.com https://example.com")]
          (is (= coerced nil))))
      (testing "Query params in the redirect URIs are retained"
        (let [uri "https://example.com?key=value"
              coerced (spec/coerce-uris uri)]
          (is (= coerced [uri]))))
      (testing "The redirect URIs may not contain a fragment"
        (let [coerced (spec/coerce-uris "https://example.com#fragment")]
          (is (= coerced nil)))))))

(deftest client-id-auth
  (testing "Based on authorization header"
    (testing "Has to be a `Basic` header")
    (testing "It has to be Base64-encoded"))
  (testing "Based on param"
    (testing "Has to be a known `client_id`")))

(deftest client-secret-auth
  (with-redefs [kitsune.db.oauth/find-for-session
                 (fn [_ {:keys [client-id client-secret]}]
                   (and (= client-id "Zm9v")
                        (= client-secret "YmFy")))]
    (testing "Based on authorizeation header"
      (let [correct "Zm9v:YmFy"]
        (testing "Has to be a `Basic` header"
          (is (handlers/app-from-request
                {:headers {"Authorization" (str "Basic " correct)}}))
          (is (not (handlers/app-from-request
                     {:headers {"Authorization" (str "Bearer " correct)}})))))
      (testing "Credentials format"
        (testing "Base64-encoded"
          (is (not (handlers/app-from-request
                    {:headers {"Authorization" (str "Basic " "hog@\"e:oo")}}))))
        (testing "Separated by a colon"
          (is (not (handlers/app-from-request
                     {:headers {"Authorization" (str "Basic " "Zm9v-YmFy")}}))))))
    (testing "Based on parameters"
      (testing "Has to be a matching known pair of `client_id` and `client_secret`"))
    (testing "Header authn takes precedence")))

(deftest authorization-verification
  ; (app-identification)
  (testing "App authn failure") ; display error
  (testing "Response type"
    (testing "Only `code` is supported")) ; unsupported_response_type
  (testing "Scope validation"
    (testing "Must be a subset of those registered with the app")) ; invalid_scope
  (testing "Relay `state`"
    (testing "Gets passed on correctly"))
  (testing "Redirect URI"
    (testing "Must be one of those registered with the app"))) ; display error

(deftest authorization
  ; (authorization-verification)
  (testing "Authorization request"
    (testing "User authentication failure"
      (testing "Displays the form again"))
    (testing "Confirms user authorization"
      (testing "If granted issues expiring `Bearer` token") ; `code` and `expires_in`
      (testing "Denied")))) ; access_denied

(deftest token-exchange
  ; (app-identification)
  (testing "Grant type `authorization_code`"
    (testing "Correct `code` parameter required") ; invalid_grant
    (testing "Each `code` may only be used once"))
  (testing "Grant type `refresh_token`"
    ; not sure if this is required -- have to check with app developers
    ; (testing "`client_secret` app authentication required") ; invalid_client
    (testing "Correct `refresh_token` parameter required")) ; invalid_grant
  (testing "Grant type `password`"
    (testing "Correct `username` and `password` rqeuired"))) ; access_denied
