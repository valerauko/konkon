(defproject social.kitsune/kitsune "0.2.0"
  :description "Very fox microblogging service"
  :url "https://kitsune.social"
  :license {:name "GNU AFFERO GENERAL PUBLIC LICENSE"
            :url "https://www.gnu.org/licenses/agpl-3.0.en.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [org.clojure/tools.namespace "0.2.11"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [ch.qos.logback/logback-classic "1.2.3"]
                 [ch.qos.logback.contrib/logback-json-classic "0.1.5"]
                 [ch.qos.logback.contrib/logback-jackson "0.1.5"]
                 [cprop "0.1.13"]
                 [mount "0.1.15"]
                 [aleph "0.4.6"]
                 [byte-streams "0.2.4"]
                 [camel-snake-kebab "0.4.0"]
                 [metosin/reitit "0.2.9"]
                 [metosin/spec-tools "0.8.2"]
                 [metosin/muuntaja "0.6.1"]
                 [metosin/ring-http-response "0.9.1"]
                 [metosin/jsonista "0.2.2"]
                 [ring/ring-defaults "0.3.2"]
                 [ring-cors "0.1.12"]
                 [org.bovinegenius/exploding-fish "0.3.6"]
                 [org.postgresql/postgresql "42.2.5"]
                 [com.layerware/hugsql "0.4.9"]
                 [hikari-cp "2.6.0"]
                 [ragtime "0.7.2"]
                 [social.kitsune/vuk "0.2.0"]
                 [social.kitsune/csele "0.4.3"]
                 [social.kitsune/karak "0.1.1"]
                 [cljstache "2.0.1"]]
  :main ^:skip-aot kitsune.core
  :target-path "target/%s"
  :jvm-opts ["-Xmx600m" "-server"]
  :profiles {:uberjar {:aot :all
                       :source-paths ["config/prod"]
                       :uberjar-name "kitsune.jar"}
             :dev {:dependencies [[org.clojure/test.check "0.9.0"]]
                   :source-paths ["config/dev"]
                   :plugins [[jonase/eastwood "0.3.4"
                              :exclusions [org.clojure/clojure]]
                             [lein-kibit "0.1.6"]
                             [lein-cloverage "1.0.13"
                              :exclusions [org.clojure/clojure]]
                             [lein-ancient "0.6.15"]]}})
