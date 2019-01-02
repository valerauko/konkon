(ns kitsune.db.core
  (:require [hikari-cp.core :refer [make-datasource close-datasource]]
            [hugsql.core]
            [hugsql.adapter :refer [result-one result-many]]
            [mount.core :refer [defstate]]
            [clojure.java.jdbc :as jdbc]
            [camel-snake-kebab.extras :refer [transform-keys]]
            [camel-snake-kebab.core :refer [->kebab-case-keyword]]
            [kitsune.instance :refer [config]])
  (:import org.postgresql.jdbc.PgArray))

(defstate datasource
  :start
  (make-datasource {:server-name   (get-in config [:db :host])
                    :adapter       "postgresql"
                    :database-name (get-in config [:db :db])
                    :username      (get-in config [:db :user])
                    :password      (get-in config [:db :pass])})
  :stop
  (close-datasource datasource))

(defstate conn
  :start {:datasource datasource})

(defn int!
  [input]
  (if (number? input)
    input
    (try
      (Integer/parseInt input)
      (catch Exception _
        0))))

(extend-protocol jdbc/IResultSetReadColumn
  org.postgresql.jdbc.PgArray
  (result-set-read-column [value metadata index]
    (vec (.getArray value))))

; these are from luminus too
(defn result-one-snake->kebab
  [this result options]
  (transform-keys ->kebab-case-keyword
                  (result-one this result options)))

(defn result-many-snake->kebab
  [this result options]
  (map #(transform-keys ->kebab-case-keyword %)
       (result-many this result options)))

(defmethod hugsql.core/hugsql-result-fn :1 [sym]
  'kitsune.db.core/result-one-snake->kebab)

(defmethod hugsql.core/hugsql-result-fn :one [sym]
  'kitsune.db.core/result-one-snake->kebab)

(defmethod hugsql.core/hugsql-result-fn :* [sym]
  'kitsune.db.core/result-many-snake->kebab)

(defmethod hugsql.core/hugsql-result-fn :many [sym]
  'kitsune.db.core/result-many-snake->kebab)
