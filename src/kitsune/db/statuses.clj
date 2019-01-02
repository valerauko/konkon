(ns kitsune.db.statuses
  (:require [kitsune.db.core :refer [conn]]
            [kitsune.uri :refer [url]]
            [hugsql.core :refer [def-db-fns]]
            [kitsune.db.user :as user-db]
            [clojure.java.jdbc :as jdbc])
  (:import java.util.UUID))

(def-db-fns "sql/activitypub.sql")

(defn uuid
  []
  (str (UUID/randomUUID)))

(defn new-status-uri
  []
  (str (url (str "/objects/" (uuid)))))

(defn new-activity-uri
  []
  (str (url (str "/activities/" (uuid)))))

(defn known-activity?
  [uri]
  (activity-exists? conn {:uri uri}))

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
  [& {:keys [content actor to cc in-reply-to-id in-reply-to-user-id]}]
  (jdbc/with-db-transaction [tx conn]
    (if-let [object (create-object! tx {:type "Note"
                                        :uri (-> "/objects/" url str)
                                        :account-id actor
                                        :to to
                                        :cc cc
                                        :content content
                                        :in-reply-to-id in-reply-to-id
                                        :in-reply-to-user-id in-reply-to-user-id})]
      (if-let [activity (create-activity! tx {:type "Create"
                                              :uri (-> "/activities/" url str)
                                              :object-id (:id object)
                                              :account-id actor
                                              :to to
                                              :cc cc})]
        {:object object :activity activity}))))

(defn preload-stuff
  "Preload:
   * users (actor and object user)"
  [activities]
  (let [ids-list (reduce
                   (fn [store activity]
                     {:users (into
                               (:users store)
                               [(:account-id activity)
                                (:object-account-id activity)])})
                   {:users #{}}
                   activities)
        raw-vec (do (println ids-list) (user-db/load-by-id conn {:ids (:users ids-list)}))
        preloaded {:users (reduce
                            (fn [aggr row]
                              (assoc aggr (:id row) row))
                            {}
                            raw-vec)}]
    (reduce
      (fn [aggr activity]
        (conj aggr
          (assoc activity :actor
            (get-in preloaded [:users (:account-id activity)]))))
      []
      activities)))
