(ns kitsune.db.statuses
  (:require [kitsune.db.core :refer [conn]]
            [kitsune.instance :refer [url]]
            [hugsql.core :refer [def-db-fns]]
            [kitsune.db.user :as user-db]
            [clojure.java.jdbc :as jdbc])
  (:import java.util.UUID))

(def-db-fns "sql/activitypub.sql")

(defn uuid
  []
  (.toString (UUID/randomUUID)))

(defn new-status-uri
  []
  (str (url (str "/objects/" (uuid)))))

(defn new-activity-uri
  []
  (str (url (str "/activities/" (uuid)))))

; TODO: split into AP library
(def public-id "https://www.w3.org/ns/activitystreams#Public")

(defn visibility
  [status]
  (cond
    (some #{public-id} (:to status)) :public
    (some #{public-id} (:cc status)) :unlisted
    (some #{(-> status :actor :followers)} (:to status)) :private
    :else :direct))

(defn create-status!
  [people data]
  (jdbc/with-db-transaction [tx conn]
    (if-let [object (create-object! tx (merge {:type "Note"
                                               :uri (new-status-uri)}
                                              people
                                              data))]
      (if-let [activity (create-activity! tx (merge {:type "Create"
                                                     :uri (new-activity-uri)}
                                                    people
                                                    {:object-id (:id object)}))]
        {:object object :activity activity}))))

(defn preload-stuff
  "Preload:
   * users (actor and object user)"
  [activities]
  (let [ids-list (reduce
                   (fn [store activity]
                     {:users (into
                               (:users store)
                               [(:user-id activity)
                                (:object-user-id activity)])})
                   {:users #{}}
                   activities)
        raw-vec (user-db/load-by-id conn {:ids (:users ids-list)})
        preloaded {:users (reduce
                            (fn [aggr row]
                              (assoc aggr (:id row) row))
                            {}
                            raw-vec)}]
    (println preloaded)
    (reduce
      (fn [aggr activity]
        (conj aggr
          (assoc activity :actor
            (get-in preloaded [:users (:user-id activity)]))))
      []
      activities)))