(ns kitsune.oauth-test
  (:require [clojure.test :refer :all]
            [kitsune.spec.oauth :as spec]))

(deftest app-registration
  (testing "App registration"
    (testing "Scope validation"
      (testing "At least one scope is required"
        (let [coerced (spec/coerce-scopes nil)]
          (is (= coerced nil)))
        (let [coerced (spec/coerce-scopes "")]
          (is (= coerced nil))))
      (testing "Unkowm scopes are ignored"
        (let [coerced (spec/coerce-scopes "read write hoge")]
          (is (= coerced ["read write"])))))
    (testing "Redirect URI validation"
      (testing "Given none or the default, the default is used"
        (let [coerced (spec/coerce-uris nil)]
          (is (= coerced ["urn:ietf:wg:oauth:2.0:oob"]))))
      (testing "All given redirect URIs have to be absolute URIs"
        (let [coerced (spec/coerce-uris "./usr/local/hoge https://example.com")]
          (is (= coerced nil))))
      (testing "Only HTTPS redirect URIs are allowed"
        (let [coerced (spec/coerce-uris "http://example.com https://example.com")]
          (is (= coerced nil))))
      (testing "Query params in the redirect URIs are retained"
        (let [uri "https://example.com?key=value"
              coerced (spec/coerce-uris uri)]
          (is (= coerced [uri]))))
      (testing "The redirect URIs may not contain a fragment"
        (let [coerced (spec/coerce-uris "https://example.com#fragment")]
          (is (= coerced nil)))))))

(deftest app-identification
  (testing "Based on authorization header"
    (testing "Uses `Basic` Authorization header"))
  (testing "Based on `client_id` param"
    (testing "Requires the matching `redirect_uri`")))

(deftest app-verification
  (testing "App verification"
    ; (app-identification)
    (testing "Returns the app associated with the given credentials")))

(deftest authorization-verification
  ; (app-identification)
  (testing "App authn failure") ; display error
  (testing "Response type"
    (testing "Only `code` is supported")) ; unsupported_response_type
  (testing "Scope validation"
    (testing "At least one scope is required")
    (testing "Unknown scopes are ignored")
    (testing "Must be a subset of those registered with the app")) ; invalid_scope
  (testing "Relay `state`"
    (testing "Gets passed on correctly"))
  (testing "Redirect URI"
    (testing "Given none, default is used")))

(deftest authorization-form
  ; (authorization-verification)
  (testing "Display authorization form"))

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
