-- :name create-app! :<! :1
insert into apps (name,
  --~ (if (not-empty (:redirect-uris params)) "redirect_uris,")
  scopes, website)
  values (:name,
  --~ (if (not-empty (:redirect-uris params)) "array[:v*:redirect-uris],")
  array[:v*:scopes], :website)
  returning id, client_id, secret as client_secret

-- :name find-for-auth :? :1
select id from apps
  where client_id = :client-id and :redirect-uri = any(redirect_uris)
  limit 1

-- :name find-for-session :? :1
select id from apps
  where client_id = :client-id and
    secret = :client-secret and :redirect-uri = any(redirect_uris)
  limit 1

-- :name create-auth! :<! :1
insert into oauth_auths (user_id, app_id, scopes)
  values (:user-id, :app-id, array[:v*:scopes])
  on conflict do nothing
  returning auth_code

-- :name use-authz! :<! :1
update oauth_auths
  set used = true
  where
    (not used) and
    app_id = :app-id and
    auth_code = :auth-code and
    expires_at > now()
  returning user_id, app_id, scopes

-- :name exchange-token! :<! :1
insert into oauth_tokens (user_id, app_id, scopes)
  values (:user-id, :app-id, array[:v*:scopes])
  returning user_id, token, refresh, scopes

-- :name find-bearer :? :1
select user_id, app_id, scopes from oauth_tokens
  where token = :token and expires_at > now()
  limit 1

-- :name find-by-refresh-token :? :1
select id from oauth_tokens
  where refresh = :refresh-token and app_id = :app-id
  limit 1

-- :name refresh-token! :<! :1
update oauth_tokens
  set
    token = default,
    refresh = default,
    expires_at = default,
    updated_at = default
  where id = :id
  returning token, refresh, scopes
