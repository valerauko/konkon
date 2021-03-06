-- :name count-local-users :? :1
select count(id) as local from users;

-- :name count-local-users-active :? :1
select count(id) as local from users
  where last_login > now() - :months * interval '1 month'

-- :name count-local-statuses :? :1
select count(id) as local from objects where local = true and type = 'Note';
