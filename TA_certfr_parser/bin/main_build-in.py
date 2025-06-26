import requests
import ssl
import json
import os
import re
import sys
from datetime import date
from html.parser import HTMLParser
import socket
import configparser
import locale
import warnings
from urllib3.exceptions import InsecureRequestWarning
from collections import OrderedDict

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certificates.
warnings.simplefilter('ignore', InsecureRequestWarning)

# --- Debugging prints ---
# print("--- INFO: Démarrage du script ---")
# print(f"Encodage stdout de Python: {sys.stdout.encoding}")
# print(f"Encodage de la locale préférée: {locale.getpreferredencoding()}")
# print(f"Locale actuelle: {locale.getlocale()}")
# print("---------------------------------")


# --- Configuration robuste pour Splunk ---
# Le script sera dans $SPLUNK_HOME/etc/apps/YourApp/bin/
# Les configs et données seront dans le répertoire de l'app
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(APP_ROOT, 'local', 'inputs.conf')
STATE_FILE = os.path.join(APP_ROOT, 'data', 'tmp.json')

# Read configuration
config = configparser.ConfigParser()
# Si le fichier de conf n'existe pas, on utilise des valeurs par défaut
if not os.path.exists(CONFIG_FILE):
    print(f"AVERTISSEMENT: Fichier de configuration non trouvé à {CONFIG_FILE}. Utilisation des valeurs par défaut.", file=sys.stderr)
    config['network'] = {
        'proxy': '',
        'target_hostname': 'www.cert.ssi.gouv.fr',
        'feed_path': '/avis/feed/'
    }
else:
    #print(f"INFO: Lecture du fichier de configuration: {CONFIG_FILE}")
    config.read(CONFIG_FILE)

# Network settings
PROXY = "" # si vous vouler passer par un proxy remplisez la variable avec votre proxy 
TARGET_HOSTNAME = config.get('network', 'target_hostname', fallback='www.cert.ssi.gouv.fr')
FEED_PATH = config.get('network', 'feed_path', fallback='/avis/feed/')
FEED_URL = f"https://{TARGET_HOSTNAME}{FEED_PATH}"

# print(f"INFO: Valeur du proxy récupérée: {PROXY}")
# print(f"INFO: URL du flux RSS configurée: {FEED_URL}")
# if PROXY:
#     print(f"INFO: Proxy configuré: {PROXY}")


def fetch_url(url, proxy=PROXY):
    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy,
        }
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    if proxies:
        # print(f"INFO: Début du téléchargement de l'URL: {url} via le proxy {proxy}")
        pass
    else:
        # print(f"INFO: Début du téléchargement de l'URL: {url} (sans proxy)")
        pass

    # --- AJOUT IMPORTANT ---
    # On ajoute verify=False pour bypasser la vérification du certificat SSL.
    # Un message d'avertissement est ajouté pour la traçabilité.
    # print("AVERTISSEMENT: La vérification du certificat SSL est désactivée (verify=False).", file=sys.stderr)
    
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15, verify=False)
        response.raise_for_status()
        #print(f"INFO: URL {url} téléchargée avec succès (status: {response.status_code}).")
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"ERREUR: [fetch_url] Erreur lors de la requête vers {url}: {e}", file=sys.stderr)
        if e.response is not None:
             print(f"ERREUR: [fetch_url] Statut de la réponse: {e.response.status_code}", file=sys.stderr)
             print(f"ERREUR: [fetch_url] Contenu de la réponse: {e.response.text}", file=sys.stderr)
        return None

def search_cve(urlfeed):
    dates = date.today()
    current_year = dates.year
    #print(f"INFO: Recherche des CVEs de l'année {current_year} depuis le flux {urlfeed}")
    try:
        body = fetch_url(urlfeed)
        if body is None:
            print("ERREUR: [search_cve] Impossible de récupérer le contenu de l'URL, abandon.", file=sys.stderr)
            return []
    except Exception as e:
        print(f"ERREUR: Erreur fetch URL {urlfeed} : {e}", file=sys.stderr)
        return []

    items = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        for bloc in root.findall("./channel/item"):
            titre_element = bloc.find("title")
            if titre_element is None or titre_element.text is None:
                print("AVERTISSEMENT: Balise 'title' manquante ou vide dans un item du flux RSS, item ignoré.", file=sys.stderr)
                continue

            verif = titre_element.text.split()
            if not any(word == str(current_year) + ")" for word in verif):
                continue
            
            link_element = bloc.find("guid")
            if link_element is None or link_element.text is None:
                print("AVERTISSEMENT: Balise 'guid' manquante ou vide dans un item du flux RSS, item ignoré.", file=sys.stderr)
                continue
            link = link_element.text

            pub_date_element = bloc.find("pubDate")
            pub_date = pub_date_element.text if pub_date_element is not None and pub_date_element.text is not None else ""
            
            titre = titre_element.text
            items.append({"url": link, "pubDate": pub_date, "titre": titre})
    except Exception as e:
        print(f"ERREUR: Erreur lors du parsing XML: {e}", file=sys.stderr)

    #print(f"INFO: {len(items)} alertes trouvées pour l'année en cours.")
    return items

def clean_text(text):
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text.strip())
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    return text

def extract_sections(html):
    excluded_sections = {"documentation", "gestion detaillee du document", "solutions"}

    class SimpleParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.in_article = False
            self.in_h2 = False
            self.current_section = None
            self.sections = {}
            self.capture_data = False
            self.current_data = ""

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "section" and attrs.get("class") == "article-content":
                self.in_article = True
            elif self.in_article and tag == "h2":
                self.in_h2 = True
            elif self.in_article and tag in ("p", "li", "a"):
                self.capture_data = True

        def handle_endtag(self, tag):
            if tag == "section":
                self.in_article = False
            elif tag == "h2":
                self.in_h2 = False
            elif tag in ("p", "li", "a"):
                if self.capture_data and self.current_section and self.current_section not in excluded_sections:
                    clean = clean_text(self.current_data)
                    if clean:
                        self.sections.setdefault(self.current_section, []).append(clean)
                self.capture_data = False
                self.current_data = ""

        def handle_data(self, data):
            if self.in_h2:
                section_name = clean_text(data.lower())
                section_name = re.sub(r'[^a-z0-9 ]', '', section_name)
                section_name = re.sub(r' +', ' ', section_name).strip()
                if section_name == "risques":
                    section_name = "risque"
                self.current_section = section_name
            elif self.capture_data:
                self.current_data += data

    parser = SimpleParser()
    parser.feed(html)
    return parser.sections

def match_version(reportUrl):
    try:
        html_bytes = fetch_url(reportUrl)
        if html_bytes is None:
            print(f"ERREUR: Impossible de récupérer {reportUrl} dans match_version.", file=sys.stderr)
            return {"URL": reportUrl, "error": "fetch failed"}
        
        #print(f"INFO: Décodage du contenu de {reportUrl} en UTF-8.")
        html = html_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"ERREUR: Erreur fetch_url ou decode dans match_version pour {reportUrl}: {e}", file=sys.stderr)
        return {"URL": reportUrl}

    result = {"URL": reportUrl}
    #print(f"INFO: Extraction des sections pour {reportUrl}")
    sections = extract_sections(html)
    result.update(sections)
    return result

def pull_data(url):
    #print(f"INFO: Lancement de la collecte des données depuis {url}")
    urlPool = search_cve(url)
    alertes = []

    for report in urlPool:
        alerte = match_version(report["url"])
        alerte["pubDate"] = report["pubDate"]
        alerte["titre"] = report["titre"]
        # Réordonner les clés pour que 'titre' soit avant 'risque' (et les autres sections dynamiques)
        ordered = OrderedDict()
        ordered["titre"] = alerte.get("titre", "")
        ordered["URL"] = alerte.get("URL", "")
        ordered["pubDate"] = alerte.get("pubDate", "")
        if "risque" in alerte:
            ordered["risque"] = alerte["risque"]
        for k, v in alerte.items():
            if k not in ordered and k not in ("titre", "URL", "pubDate", "risque"):
                ordered[k] = v
        alertes.append(ordered)
        # Impression retirée d'ici
    #print(f"INFO: {len(alertes)} alertes ont été traitées.")
    return alertes

def create_tmp(url):
    alertes = pull_data(url)
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    #print(f"INFO: Écriture de {len(alertes)} alertes dans le fichier de statut (tmp) : {STATE_FILE}")
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(alertes, f, ensure_ascii=False, indent=2)
        #print(f"INFO: Fichier de statut {STATE_FILE} créé/mis à jour avec succès.")
    except IOError as e:
        print(f"ERREUR: Erreur d'écriture dans le fichier {STATE_FILE}: {e}", file=sys.stderr)

    # Pour Splunk, lors de la première exécution, on envoie toutes les alertes
    for alerte in alertes:
        print(json.dumps(alerte, ensure_ascii=False))

def entry_compare(url):
    update = []
    data = pull_data(url)

    if not os.path.exists(STATE_FILE) or os.path.getsize(STATE_FILE) == 0:
        print(f"AVERTISSEMENT: Fichier de statut {STATE_FILE} vide ou inexistant. Création et envoi des données initiales...", file=sys.stderr)
        create_tmp(url)
        return

    try:
        #print(f"INFO: Lecture du fichier de statut existant : {STATE_FILE}")
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            tmp = json.load(f)
        #print(f"INFO: {len(tmp)} entrées lues depuis {STATE_FILE}.")
    except (ValueError, json.JSONDecodeError) as e:
        print(f"ERREUR: Fichier de statut {STATE_FILE} invalide. Recréation... Erreur: {e}", file=sys.stderr)
        create_tmp(url)
        return
    except IOError as e:
        print(f"ERREUR: Impossible de lire le fichier {STATE_FILE}: {e}", file=sys.stderr)
        return

    tmp_url = set(entry.get("URL") for entry in tmp if "URL" in entry)
    current_url = set(entry.get("URL") for entry in data if "URL" in entry)

    new_urls = current_url - tmp_url

    if not new_urls:
        # print("INFO: Aucune nouvelle URL à traiter pour Splunk.")
        pass
    else:
        #print(f"INFO: {len(new_urls)} nouvelle(s) URL(s) trouvée(s). Traitement en cours...")
        for url_ in new_urls:
            alerte_details = match_version(url_)
            pubdate = next((d["pubDate"] for d in data if d.get("URL") == url_), "")
            titre = next((d["titre"] for d in data if d.get("URL") == url_), "")
            alerte_details["pubDate"] = pubdate
            alerte_details["titre"] = titre
            # Réordonner les clés comme dans pull_data
            ordered = OrderedDict()
            ordered["titre"] = alerte_details.get("titre", "")
            ordered["URL"] = alerte_details.get("URL", "")
            ordered["pubDate"] = alerte_details.get("pubDate", "")
            if "risque" in alerte_details:
                ordered["risque"] = alerte_details["risque"]
            for k, v in alerte_details.items():
                if k not in ordered and k not in ("titre", "URL", "pubDate", "risque"):
                    ordered[k] = v
            update.append(ordered)
            print(json.dumps(ordered, ensure_ascii=False))

        # Met à jour le fichier de statut avec les nouvelles entrées
        #print(f"INFO: Mise à jour du fichier de statut {STATE_FILE} avec {len(update)} nouvelle(s) entrée(s).")
        tmp.extend(update)
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(tmp, f, ensure_ascii=False, indent=2)
            print(f"INFO: Fichier {STATE_FILE} mis à jour avec succès.")
        except IOError as e:
            print(f"ERREUR: Erreur d'écriture lors de la mise à jour de {STATE_FILE}: {e}", file=sys.stderr)

def main(mainUrl):
    # print("INFO: Démarrage du script principal.")
    entry_compare(mainUrl)
    # print("INFO: Fin du script principal.")

if __name__ == "__main__":
    main(FEED_URL) 
