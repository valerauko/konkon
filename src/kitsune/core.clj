(ns kitsune.core
  (:require [clojure.tools.logging :as log]
            [aleph.http :as http]
            [mount.core :refer [defstate start stop]]
            [kitsune.instance :refer [config]]
            [kitsune.env :as env]
            [kitsune.db.core :refer [conn]]
            [kitsune.routes.core :as routes]
            [kitsune.db.migrations :as migrations])
  (:gen-class))

(defstate ^{:on-reload :noop} http-server
  :start
    (http/start-server
      (env/wrap routes/wrapped-handler)
      {:port (get-in config [:server :port])
       :compression true})
  :stop
    (.close ^java.io.Closeable http-server))

(defn stop-server
  []
  (doseq [component (:stopped (stop))]
    (log/debug component "stopped"))
  (shutdown-agents))

(defn start-server
  []
  (doseq [component (:started (start))]
    (log/debug component "started"))
  (.addShutdownHook (Runtime/getRuntime)
                    (Thread. ^Runnable stop-server)))

(defn -main [& args]
  (cond
    (some #{"migrate"} args) (do (start #'kitsune.instance/config
                                        #'kitsune.db.core/datasource
                                        #'kitsune.db.core/conn)
                                 (migrations/migrate conn)
                                 (System/exit 0))
    (some #{"rollback"} args) (do (start #'kitsune.instance/config
                                         #'kitsune.db.core/datasource
                                         #'kitsune.db.core/conn)
                                  (migrations/rollback conn)
                                  (System/exit 0))
    :else (start-server)))
