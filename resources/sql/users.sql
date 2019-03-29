-- :name create-user! :<! :1
-- :doc Creates a new user record and returns its ID
insert into users
  (email, name, pass_hash, private_key)
  values (:email, :name, :pass-hash, :private-key)
  returning id

-- :name create-account! :<! :1
-- :doc Creates a new account record. Used both for local and remote
insert into accounts
  (user_id, acct, uri, local, public_key, display_name, inbox, shared_inbox)
  values (
    --~ (if (:user-id params) ":user-id" "NULL")
    , :acct, :uri,
    --~ (if (:local params) "true" "false")
    , :public-key,
    --~ (if (:display-name params) ":display-name" "NULL")
    , :inbox, :shared-inbox
  )
  returning id

-- :name update! :<! :1
update accounts
  set display_name = :display-name
  where user_id = :id
  returning *

-- :name update-account! :<! :1
update accounts set
/*~
(->> (dissoc params :uri)
     (map (fn [[key _]]
            (str (camel-snake-kebab.core/->snake_case_string key)
                 "=" key)))
     (clojure.string/join ", "))
~*/
where lower(uri) = :uri
returning *

-- :name update-private-key! :<! :1
update users
  set private_key = :private-key
  where id = :id

-- :name update-public-key! :<! :1
update accounts
  set public_key = :public-key
  where user_id = :user-id

-- :name touch-last-login! :<! :1
update users
  set last_login = now()
  where id = :id
  returning true as result

-- :name destroy! :<! :1
delete from users
  where name = :name
  returning true as result

-- :name count-followers :? :1
select accounts.id as id, accounts.uri, count(follows.id) as followers
  from users join accounts on accounts.user_id = users.id
  left join follows on accounts.id = follows.followed
  where users.name = :name
  group by accounts.id, accounts.uri
  limit 1

-- :name followers-of :? :*
select accounts.uri from accounts
  right join follows on accounts.id = follows.follower
  where follows.followed = :id
  order by follows.created_at desc
  offset :offset
  limit :limit

-- :name count-following :? :1
select accounts.id as id, accounts.uri, count(follows.id) as following
  from users join accounts on accounts.user_id = users.id
  left join follows on accounts.id = follows.follower
  where users.name = :name
  group by accounts.id, accounts.uri
  limit 1

-- :name followed-by :? :*
select accounts.uri from accounts
  right join follows on accounts.id = follows.followed
  where follows.follower = :id
  order by follows.created_at desc
  offset :offset
  limit :limit

-- :name find-for-auth :? :1
select id from users where email = :email and pass_hash = :pass-hash

-- :name find-by-name :? :1
select * from accounts
join users on accounts.user_id = users.id
where name = :name and local = true limit 1

-- :name find-by-id :? :1
select *, accounts.id as account_id from accounts
left join users on users.id = accounts.user_id
where accounts.id = :id::int limit 1

-- :name find-by-user-id :? :1
select *, accounts.id as account_id from users
left join accounts on users.id = accounts.user_id
where users.id = :id::int limit 1

-- :name find-by-uri :? :1
select * from accounts
left join users on accounts.user_id = users.id
where uri = :uri limit 1

-- :name find-by-acct :? :1
select * from accounts
join users on accounts.user_id = users.id
where acct = :acct limit 1

-- :name load-by-id :? :*
select * from accounts where id in (:v*:ids)
