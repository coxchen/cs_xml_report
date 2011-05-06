(use 'clojure.xml)

;;;;;;;;;;;;;;;;;;;;;;;
;; xml-report functions

(defn get-vulns [the-xml-report]
  (filter #(= :rd:vulnerability (:tag %)) (xml-seq the-xml-report)))

(defn get-vuln-type [a-vuln]
  (:type (:attrs a-vuln)))

(defn filter-vulns [vuln-type the-vulns]
  (filter #(= vuln-type (get-vuln-type %)) the-vulns))

(defn get-vuln-types [the-vulns]
  (distinct (map #(get-vuln-type %) the-vulns)))

(defn get-sink-file [a-vuln]
  (:path (:attrs (first (:content (first (:content a-vuln)))))))

(defn get-sink-file-name [a-vuln]
  (:name (:attrs (first (:content (first (:content a-vuln)))))))

(defn get-sink-lineno [a-vuln]
  (:sl (:attrs (first (:content a-vuln)))))

(defn get-vuln-stmt [a-vuln]
  (format "%s#%s"
          (get-sink-file-name a-vuln)
          (get-sink-lineno a-vuln)))

(defn get-tb-count [a-vuln]
  (count (filter #(= :tr:traceback (:tag %)) (xml-seq a-vuln))))

(defn get-vuln-abstract [a-vuln]
  [(get-vuln-type a-vuln)
   (get-vuln-stmt a-vuln)
   (get-tb-count a-vuln)])

(defn view-vulns-abstract [the-vulns]
  (view
   (dataset
    ["Type" "Vuln Stmt" "TB Count"]
    (map get-vuln-abstract the-vulns))))

(defn get-sink-files [the-vulns]
  (distinct (map get-sink-file the-vulns)))

(defn get-scan-files [the-xml-report]
  (filter #(= :rd:scanfile (:tag %)) (xml-seq the-xml-report)))

(defn get-scan-file-names [xml-report]
  (map
   #(:path (:attrs %))
   (get-scan-files xml-report)))

(defn isScanned?
  "true if a given file name is in the scanned file list"
  [scanned-files a-file-name]
  (in? scanned-files a-file-name))
