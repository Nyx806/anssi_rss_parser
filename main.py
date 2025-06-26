import requests
import pandas as pd
import os
import json
from datetime import date
from lxml import etree
from bs4 import BeautifulSoup
import re

url = "https://www.cert.ssi.gouv.fr/alerte/feed/"
avisUrl = "https://www.cert.ssi.gouv.fr/avis/feed/"
file_check = "update.json"

proxies = {
    'http': 'http://proxyprovider.com:2000',
    'https': 'http://proxyprovider.com:2000',
}

def search_cve(urlfeed): 
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'}
    
    dates = date.today()
    current_year = dates.year
    
    r = requests.get(urlfeed, headers=headers, verify=True)
    print(f"Réponse du site : {r}")
    if r.status_code == 200:
        body = r.content
        root = etree.fromstring(body)
        items = []
        for bloc in root.findall("./channel/item"):
            titre = bloc.find("title")
            verif = titre.text.split()
            for word in verif:
                if word == str(current_year) + ")":
                    link = bloc.find("guid").text
                    pub_date = bloc.find("pubDate").text if bloc.find("pubDate") is not None else ""
                    items.append({"url": link, "pubDate": pub_date})
    return items

def clean_text(text):
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text.strip())
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    return text

def match_version(reportUrl):
    headers = {'User-Agent': 'Mozilla/5.0'}
    r = requests.get(reportUrl, headers=headers, verify=True)
    soup = BeautifulSoup(r.content, 'html.parser')
    
    result = {"URL": reportUrl}
    current_title = None

    section = soup.select_one("section.article-content")
    if not section:
        return result

    excluded_sections = ["documentation", "gestion detaillee du document", "solutions"]

    for tag in section.find_all(['h2', 'ul', 'p', 'a'], recursive=True):
        if tag.name == 'h2':
            current_title = tag.get_text(strip=True).lower()
            current_title = re.sub(r'[^a-z0-9 ]', '', current_title)
            current_title = re.sub(r' +', ' ', current_title).strip()
            if current_title == "risques":
                current_title = "risque"
            if current_title not in excluded_sections:
                result[current_title] = []
        elif current_title and current_title not in excluded_sections:
            if tag.name == 'ul':
                for li in tag.find_all('li'):
                    text = clean_text(li.get_text(strip=True))
                    if text:  # N'ajoute que si le texte n'est pas vide
                        result[current_title].append(text)
            elif tag.name == 'p':
                text = clean_text(tag.get_text(strip=True))
                if text:  # N'ajoute que si le texte n'est pas vide
                    result[current_title].append(text)
            elif tag.name == 'a':
                href = tag.get('href')
                if href:  # N'ajoute que si le lien n'est pas vide
                    result[current_title].append(href)

    # Garde les éléments sous forme de listes pour l'export JSON
    for key in result:
        if isinstance(result[key], list):
            if not result[key]:  # Si la liste est vide
                result[key] = []

    return result

def display_dataframe(df):    
    # Créer une copie du DataFrame pour l'affichage avec retours à la ligne
    df_display = df.copy()
    for column in df_display.columns:
        if column not in ["URL", "pubDate"]:  # Ne pas modifier les URLs et dates
            df_display[column] = df_display[column].apply(lambda x: "\n".join(x) if isinstance(x, list) and x else x)
    
    print(df_display)

def pull_data(url):
    urlPool = search_cve(url)
    alertes = []
    all_fieldnames = {"URL", "pubDate"}

    for report in urlPool:
        alerte = match_version(report["url"])
        all_fieldnames.update(alerte.keys())
        alerte["pubDate"] = report["pubDate"]
        alertes.append(alerte)

    fieldnames = sorted(list(all_fieldnames))
    if "URL" in fieldnames:
        fieldnames.remove("URL")
        fieldnames.insert(0, "URL")
    if "pubDate" in fieldnames:
        fieldnames.remove("pubDate")
        fieldnames.insert(1, "pubDate")

    return alertes

def create_tmp(url):
    alertes= pull_data(url)
    with open("data/tmp.json", "w", encoding="utf-8") as f:
        json.dump(alertes, f, ensure_ascii=False, indent=2)
        for alerte in alertes:
            print(json.dumps(alerte, ensure_ascii=False))
def entry_compare(url):
    update = []

    data = pd.DataFrame(pull_data(url))

    if not os.path.exists("data/tmp.json") or os.path.getsize("data/tmp.json") == 0:
        print("Fichier tmp.json vide ou inexistant. Création...")
        create_tmp(url)
        return

    try:
        with open('data/tmp.json', 'r', encoding='utf-8') as f:
            tmp_data = json.load(f)
        tmp = pd.DataFrame(tmp_data)
    except ValueError:
        print("Fichier tmp.json invalide. Recréation...")
        create_tmp(url)
        return

    tmp_url = set(tmp["URL"])
    current_url = set(data["URL"])

    new_urls = current_url - tmp_url

    if not new_urls:
        print("Aucune nouvelle URL à ajouter.")
        return

    print(f"Nouvelles URL à ajouter : {len(new_urls)}")
    for url in new_urls:
        test = match_version(url)
        update.append(test)

    with open("data/tmp.json", "r+", encoding="utf-8") as f:
        try:
            tmp_update = json.load(f)
        except json.JSONDecodeError:
            tmp_update = []

        tmp_update.extend(update)
        f.seek(0)
        json.dump(tmp_update, f, ensure_ascii=False, indent=2)
        f.truncate()

    print(f"{len(update)} entrées ajoutées :")
    for entry in update:
        print(json.dumps(entry, ensure_ascii=False))  

def main(mainUrl):
    entry_compare(mainUrl)
    
 

main(avisUrl)
