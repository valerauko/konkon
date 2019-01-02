(ns user
  (:require [mount.core :refer [start stop] :as mount]
            [kitsune.db.core :refer [conn]]
            [kitsune.db.migrations :as migrations]
            [clojure.tools.namespace.repl :refer [refresh]]))

(defn reload
  []
  (stop)
  (refresh)
  (start))

(defn migrate
  []
  (mount/start #'kitsune.db.core/conn)
  (migrations/migrate conn))

(defn rollback
  []
  (mount/start #'kitsune.db.core/conn)
  (migrations/rollback conn))
