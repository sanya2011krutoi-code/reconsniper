#!/usr/bin/env python3
import os
import sys
import time
import json
import re
import hashlib
import sqlite3
import requests
import socket
import dns.resolver
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ============================================
# БАННЕР
# ============================================
def banner():
    os.system('clear')
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗   ███████╗███╗   ██╗║
    ║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║   ██╔════╝████╗  ██║║
    ║      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ███████╗██╔██╗ ██║║
    ║      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ╚════██║██║╚██╗██║║
    ║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ███████║██║ ╚████║║
    ║      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚══════╝╚═╝  ╚═══╝║
    ║                                                                      ║
    ║            ╔══════════════════════════════════════════════╗           ║
    ║            ║   ReconSniper v5.0 — ULTIMATE OSINT TOOL    ║           ║
    ║            ║   Developer: @remeronoff                     ║           ║
    ║            ║   FULL RECON — PHONE, EMAIL, USERNAME, IP   ║           ║
    ║            ╚══════════════════════════════════════════════╝           ║
    ║                                                                      ║
    ║  [1] 📱 Поиск по номеру телефона (полный)                           ║
    ║  [2] 📧 Поиск по email (полный)                                     ║
    ║  [3] 👤 Поиск по никнейму (100+ платформ)                          ║
    ║  [4] 🌐 Поиск по IP-адресу                                          ║
    ║  [5] 🌍 Поиск по домену (WHOIS, DNS, поддомены)                    ║
    ║  [6] 👨 Поиск по имени и фамилии (соцсети + Google)                ║
    ║  [7] 🗄️ Управление базами данных (загрузка / поиск)                ║
    ║  [8] 📊 Генерация отчёта по цели (HTML)                            ║
    ║  [0] 🚪 Выход                                                       ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚡ Ready for deep recon...\n")

# ============================================
# КОНФИГУРАЦИЯ БАЗЫ ДАННЫХ
# ============================================
DB_PATH = "recon_db.sqlite"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE,
            name TEXT,
            operator TEXT,
            region TEXT,
            country TEXT,
            carrier TEXT,
            source TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            breaches TEXT,
            source TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usernames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            name TEXT,
            platform TEXT,
            source TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            country TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            asn TEXT,
            source TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            registrar TEXT,
            creation_date TEXT,
            expiry_date TEXT,
            name_servers TEXT,
            owner TEXT,
            source TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT UNIQUE,
            result TEXT,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def save_to_cache(query, result, source="API"):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO cache (query, result, source) VALUES (?, ?, ?)",
                       (query, json.dumps(result), source))
        conn.commit()
        conn.close()
    except:
        pass

def get_from_cache(query):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT result FROM cache WHERE query = ?", (query,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None
    except:
        return None

def save_to_db(table, columns, values):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        placeholders = ','.join(['?' for _ in values])
        query = f"INSERT OR IGNORE INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
        cursor.execute(query, values)
        conn.commit()
        conn.close()
    except:
        pass

def search_local_db(table, column, value):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM {table} WHERE {column} LIKE ?"
        cursor.execute(query, (f"%{value}%",))
        results = cursor.fetchall()
        conn.close()
        return results
    except:
        return []

# ============================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================
def print_link(label, url, found=True):
    if found:
        print(f"    ✅ {label}: {url}")
    else:
        print(f"    ❌ {label}: не найден")

def print_with_link(label, url, status):
    if status:
        print(f"    ✅ {label}: {url}")
    else:
        print(f"    ❌ {label}: не найден")

# ============================================
# 1. ПОЛНЫЙ ПОИСК ПО НОМЕРУ ТЕЛЕФОНА
# ============================================
def search_phone_full(phone):
    print(f"\n[📱] ПОЛНЫЙ ПОИСК ПО НОМЕРУ: {phone}\n")
    print("═" * 70)
    
    cached = get_from_cache(f"phone_{phone}")
    if cached:
        print("[💾] Данные из кэша:\n")
        for k, v in cached.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    print(f"    {k}.{sub_k}: {sub_v}")
            else:
                print(f"    {k}: {v}")
        return
    
    results = {}
    
    # ---- 1. Локальная база ----
    print("\n[📁] ЛОКАЛЬНАЯ БАЗА ДАННЫХ:")
    local = search_local_db('phones', 'phone', phone)
    if local:
        for row in local:
            print(f"    ✅ Найдено в базе:")
            print(f"        Имя: {row[2] if row[2] else 'Неизвестно'}")
            print(f"        Оператор: {row[3] if row[3] else 'Неизвестно'}")
            print(f"        Регион: {row[4] if row[4] else 'Неизвестно'}")
            results['local_db'] = {'name': row[2], 'operator': row[3], 'region': row[4]}
    else:
        print("    ❌ Не найдено в локальной базе.")
    
    # ---- 2. Оператор и регион (API) ----
    print("\n[📡] ОПЕРАТОР, СТРАНА, РЕГИОН:")
    try:
        r = requests.get(f"https://api.phonevalidation.xyz/v1/validate?number={phone}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"    Страна: {data.get('country', 'Неизвестно')}")
            print(f"    Регион: {data.get('region', 'Неизвестно')}")
            print(f"    Оператор: {data.get('carrier', 'Неизвестно')}")
            print(f"    Тип: {data.get('type', 'Неизвестно')}")
            results['operator'] = {'country': data.get('country'), 'region': data.get('region'), 
                                   'carrier': data.get('carrier'), 'type': data.get('type')}
    except:
        print("    ❌ Ошибка определения оператора.")
    
    # ---- 3. Truecaller ----
    print("\n[📚] ТЕЛЕФОННЫЕ КНИГИ:")
    url = f"https://www.truecaller.com/search/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            name_tag = soup.find('span', class_='name')
            if name_tag:
                print(f"    ✅ Truecaller: {url}")
                results['truecaller'] = url
            else:
                print(f"    ❌ Truecaller: не найден")
        else:
            print(f"    ❌ Truecaller: не найден")
    except:
        print(f"    ❌ Truecaller: ошибка")
    
    # ---- 4. SpamCalls ----
    url = f"https://spamcalls.net/number/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            desc = soup.find('div', class_='description')
            if desc:
                print(f"    ✅ SpamCalls: {url}")
                results['spamcalls'] = url
            else:
                print(f"    ❌ SpamCalls: не найден")
        else:
            print(f"    ❌ SpamCalls: не найден")
    except:
        print(f"    ❌ SpamCalls: ошибка")
    
    # ---- 5. CallerID ----
    url = f"https://www.callerid.com/phone/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            name = soup.find('span', class_='name')
            if name:
                print(f"    ✅ CallerID: {url}")
                results['callerid'] = url
            else:
                print(f"    ❌ CallerID: не найден")
        else:
            print(f"    ❌ CallerID: не найден")
    except:
        print(f"    ❌ CallerID: ошибка")
    
    # ---- 6. GetContact ----
    print("\n[🔍] GETCONTACT:")
    url = f"https://www.google.com/search?q=getcontact+{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and "getcontact" in r.text.lower():
            print(f"    ✅ GetContact: {url}")
            results['getcontact'] = url
        else:
            print(f"    ❌ GetContact: не найден")
    except:
        print(f"    ❌ GetContact: ошибка")
    
    # ---- 7. Telegram ----
    print("\n[💬] TELEGRAM:")
    url = f"https://t.me/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            name = soup.find('div', class_='tgme_page_title')
            bio = soup.find('div', class_='tgme_page_description')
            print(f"    ✅ Найден: {url}")
            print(f"        Имя: {name.text.strip() if name else 'Неизвестно'}")
            print(f"        Био: {bio.text.strip() if bio else 'Нет био'}")
            results['telegram'] = url
        else:
            print(f"    ❌ Telegram: не найден")
    except:
        print(f"    ❌ Telegram: ошибка")
    
    # ---- 8. WhatsApp ----
    print("\n[💬] WHATSAPP:")
    url = f"https://wa.me/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['whatsapp'] = url
        else:
            print(f"    ❌ WhatsApp: не найден")
    except:
        print(f"    ❌ WhatsApp: ошибка")
    
    # ---- 9. Viber ----
    print("\n[💬] VIBER:")
    url = f"https://www.viber.com/{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['viber'] = url
        else:
            print(f"    ❌ Viber: не найден")
    except:
        print(f"    ❌ Viber: ошибка")
    
    # ---- 10. Instagram ----
    print("\n[📸] INSTAGRAM:")
    url = f"https://www.instagram.com/{phone}/"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['instagram'] = url
        else:
            print(f"    ❌ Instagram: не найден")
    except:
        print(f"    ❌ Instagram: ошибка")
    
    # ---- 11. TikTok ----
    print("\n[🎵] TIKTOK:")
    url = f"https://www.tiktok.com/@{phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['tiktok'] = url
        else:
            print(f"    ❌ TikTok: не найден")
    except:
        print(f"    ❌ TikTok: ошибка")
    
    # ---- 12. Утечки (HIBP) ----
    print("\n[🔓] УТЕЧКИ ПАРОЛЕЙ:")
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{phone}", timeout=5)
        if r.status_code == 200:
            breaches = r.json()
            print(f"    ✅ Найдено утечек: {len(breaches)}")
            for b in breaches[:5]:
                print(f"    - {b['Name']} ({b['BreachDate']})")
            results['breaches'] = [{'name': b['Name'], 'date': b['BreachDate']} for b in breaches[:5]]
        else:
            print("    ❌ Утечек не найдено.")
    except:
        print("    ❌ Ошибка проверки.")
    
    # ---- 13. Google Search ----
    print("\n[🔍] GOOGLE (первые результаты):")
    url = f"https://www.google.com/search?q={phone}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            results_google = soup.find_all('h3')
            if results_google:
                for h in results_google[:3]:
                    print(f"    - {h.text.strip()}")
                results['google'] = url
            else:
                print("    ❌ Ничего не найдено")
    except:
        print("    ❌ Ошибка")
    
    save_to_cache(f"phone_{phone}", results)
    save_to_db('phones', ['phone', 'data', 'source'], [phone, json.dumps(results), 'FullRecon'])
    print("\n" + "═" * 70)

# ============================================
# 2. ПОЛНЫЙ ПОИСК ПО EMAIL
# ============================================
def search_email_full(email):
    print(f"\n[📧] ПОЛНЫЙ ПОИСК ПО EMAIL: {email}\n")
    print("═" * 70)
    
    cached = get_from_cache(f"email_{email}")
    if cached:
        print("[💾] Данные из кэша:\n")
        for k, v in cached.items():
            print(f"    {k}: {v}")
        return
    
    results = {}
    
    # ---- 1. Локальная база ----
    print("\n[📁] ЛОКАЛЬНАЯ БАЗА:")
    local = search_local_db('emails', 'email', email)
    if local:
        for row in local:
            print(f"    ✅ Найдено: {row[2] if row[2] else 'Без имени'}")
            results['local'] = {'name': row[2], 'breaches': row[3]}
    else:
        print("    ❌ Не найдено.")
    
    # ---- 2. Утечки (HIBP) ----
    print("\n[🔓] УТЕЧКИ ПАРОЛЕЙ:")
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", timeout=5)
        if r.status_code == 200:
            breaches = r.json()
            print(f"    ✅ Найдено утечек: {len(breaches)}")
            for b in breaches[:10]:
                print(f"    - {b['Name']} ({b['BreachDate']})")
            results['hibp'] = [{'name': b['Name'], 'date': b['BreachDate']} for b in breaches[:10]]
        else:
            print("    ❌ Утечек не найдено.")
    except:
        print("    ❌ Ошибка проверки.")
    
    # ---- 3. Gravatar ----
    print("\n[🖼️] GRAVATAR:")
    url = f"https://www.gravatar.com/{hashlib.md5(email.lower().encode()).hexdigest()}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['gravatar'] = url
        else:
            print(f"    ❌ Gravatar: не найден")
    except:
        print(f"    ❌ Gravatar: ошибка")
    
    # ---- 4. Instagram ----
    print("\n[📸] INSTAGRAM:")
    url = f"https://www.instagram.com/{email}/"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['instagram'] = url
        else:
            print(f"    ❌ Instagram: не найден")
    except:
        print(f"    ❌ Instagram: ошибка")
    
    # ---- 5. GitHub ----
    print("\n[🐙] GITHUB:")
    url = f"https://github.com/{email}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['github'] = url
        else:
            print(f"    ❌ GitHub: не найден")
    except:
        print(f"    ❌ GitHub: ошибка")
    
    # ---- 6. Twitter ----
    print("\n[🐦] TWITTER:")
    url = f"https://twitter.com/{email}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"    ✅ Найден: {url}")
            results['twitter'] = url
        else:
            print(f"    ❌ Twitter: не найден")
    except:
        print(f"    ❌ Twitter: ошибка")
    
    # ---- 7. Google ----
    print("\n[🔍] GOOGLE:")
    url = f"https://www.google.com/search?q={email}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            results_google = soup.find_all('h3')
            if results_google:
                for h in results_google[:3]:
                    print(f"    - {h.text.strip()}")
                results['google'] = url
            else:
                print("    ❌ Ничего не найдено")
    except:
        print("    ❌ Ошибка")
    
    save_to_cache(f"email_{email}", results)
    save_to_db('emails', ['email', 'data', 'source'], [email, json.dumps(results), 'FullRecon'])
    print("\n" + "═" * 70)

# ============================================
# 3. ПОИСК ПО НИКНЕЙМУ (100+ ПЛАТФОРМ)
# ============================================
def search_username_full(username):
    print(f"\n[👤] ПОИСК ПО НИКНЕЙМУ: {username}\n")
    print("═" * 70)
    
    cached = get_from_cache(f"username_{username}")
    if cached:
        print("[💾] Данные из кэша:\n")
        for platform, url in cached.items():
            if url != "Не найден" and url != "Ошибка":
                print(f"    ✅ {platform}: {url}")
            else:
                print(f"    ❌ {platform}: не найден")
        return
    
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "VK": f"https://vk.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Roblox": f"https://www.roblox.com/user.aspx?username={username}",
        "Minecraft": f"https://namemc.com/search?q={username}",
        "HackerRank": f"https://www.hackerrank.com/{username}",
        "LeetCode": f"https://leetcode.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Rumble": f"https://rumble.com/user/{username}",
        "Odysee": f"https://odysee.com/@{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "Imgur": f"https://imgur.com/user/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Tinder": f"https://www.tinder.com/@{username}",
        "Bumble": f"https://bumble.com/{username}",
        "OkCupid": f"https://www.okcupid.com/profile/{username}",
        "Discord": f"https://discord.com/users/{username}",
        "Slack": f"https://slack.com/profile/{username}",
        "Skype": f"https://skype.com/profile/{username}",
        "Fiverr": f"https://www.fiverr.com/{username}",
        "Upwork": f"https://www.upwork.com/freelancers/{username}",
        "Codeforces": f"https://codeforces.com/profile/{username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "WordPress": f"https://{username}.wordpress.com",
        "Blogger": f"https://{username}.blogger.com",
        "Mastodon": f"https://mastodon.social/@{username}",
        "Bitchute": f"https://www.bitchute.com/channel/{username}",
        "Rutube": f"https://rutube.ru/channel/{username}",
        "Dailymotion": f"https://www.dailymotion.com/{username}",
        "Giphy": f"https://giphy.com/{username}",
        "Periscope": f"https://www.periscope.tv/{username}",
        "Vine": f"https://vine.co/{username}",
        "Tox": f"https://tox.com/profile/{username}",
        "Jami": f"https://jami.com/profile/{username}",
        "Matrix": f"https://matrix.com/profile/{username}",
        "Zoom": f"https://zoom.com/profile/{username}",
        "Meet": f"https://meet.google.com/profile/{username}",
        "Jitsi": f"https://jitsi.com/profile/{username}",
        "Whereby": f"https://whereby.com/profile/{username}",
        "Wickr": f"https://wickr.com/profile/{username}",
        "Wire": f"https://wire.com/profile/{username}",
        "Threema": f"https://threema.com/profile/{username}",
        "Signal": f"https://signal.org/profile/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}"
    }
    
    results = {}
    total = len(platforms)
    found = 0
    
    print(f"[+] Проверка {total} платформ...\n")
    for name, url in platforms.items():
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                print(f"    ✅ {name}: {url}")
                results[name] = url
                found += 1
                save_to_db('usernames', ['username', 'platform', 'source', 'data'],
                           [username, name, 'FullRecon', url])
            else:
                print(f"    ❌ {name}: не найден")
                results[name] = "Не найден"
        except:
            print(f"    ❌ {name}: ошибка")
            results[name] = "Ошибка"
        time.sleep(0.05)
    
    print(f"\n[+] Найдено на {found}/{total} платформах")
    
    save_to_cache(f"username_{username}", results)
    print("\n" + "═" * 70)

# ============================================
# 4. ПОИСК ПО IP-АДРЕСУ
# ============================================
def search_ip_full(ip):
    print(f"\n[🌐] ПОИСК ПО IP: {ip}\n")
    print("═" * 70)
    
    cached = get_from_cache(f"ip_{ip}")
    if cached:
        print("[💾] Данные из кэша:\n")
        for k, v in cached.items():
            print(f"    {k}: {v}")
        return
    
    results = {}
    
    # ---- 1. IP-информация ----
    print("\n[📍] ГЕОЛОКАЦИЯ И ПРОВАЙДЕР:")
    url = f"http://ip-api.com/json/{ip}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"    Страна: {data.get('country', 'Неизвестно')}")
            print(f"    Регион: {data.get('regionName', 'Неизвестно')}")
            print(f"    Город: {data.get('city', 'Неизвестно')}")
            print(f"    ISP: {data.get('isp', 'Неизвестно')}")
            print(f"    Организация: {data.get('org', 'Неизвестно')}")
            print(f"    AS: {data.get('as', 'Неизвестно')}")
            print(f"    Координаты: {data.get('lat', '')}, {data.get('lon', '')}")
            results['geo'] = data
    except:
        print("    ❌ Ошибка определения геолокации.")
    
    # ---- 2. WHOIS ----
    print("\n[📋] WHOIS:")
    url = f"https://whois.domaintools.com/{ip}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            whois_data = soup.find('pre')
            if whois_data:
                print(f"    {whois_data.text[:500]}")
                results['whois'] = url
    except:
        print("    ❌ Ошибка получения WHOIS.")
    
    # ---- 3. DNS ----
    print("\n[🌐] DNS:")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"    Хост: {hostname}")
        results['hostname'] = hostname
    except:
        print("    ❌ Хост не определён.")
    
    # ---- 4. Открытые порты ----
    print("\n[🚪] ОТКРЫТЫЕ ПОРТЫ (проверка 5 портов):")
    common_ports = [80, 443, 22, 21, 8080]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"    ✅ {port} — открыт")
                open_ports.append(port)
            sock.close()
        except:
            pass
    results['open_ports'] = open_ports
    
    # ---- 5. Google ----
    print("\n[🔍] GOOGLE:")
    url = f"https://www.google.com/search?q={ip}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            results_google = soup.find_all('h3')
            if results_google:
                for h in results_google[:3]:
                    print(f"    - {h.text.strip()}")
                results['google'] = url
    except:
        print("    ❌ Ошибка")
    
    save_to_cache(f"ip_{ip}", results)
    save_to_db('ips', ['ip', 'data', 'source'], [ip, json.dumps(results), 'FullRecon'])
    print("\n" + "═" * 70)

# ============================================
# 5. ПОИСК ПО ДОМЕНУ
# ============================================
def search_domain_full(domain):
    print(f"\n[🌍] ПОИСК ПО ДОМЕНУ: {domain}\n")
    print("═" * 70)
    
    cached = get_from_cache(f"domain_{domain}")
    if cached:
        print("[💾] Данные из кэша:\n")
        for k, v in cached.items():
            print(f"    {k}: {v}")
        return
    
    results = {}
    
    # ---- 1. WHOIS ----
    print("\n[📋] WHOIS:")
    try:
        w = whois.whois(domain)
        print(f"    Регистратор: {w.registrar}")
        print(f"    Создан: {w.creation_date}")
        print(f"    Истекает: {w.expiration_date}")
        print(f"    DNS: {w.name_servers}")
        print(f"    Владелец: {w.name}")
        results['whois'] = {
            'registrar': w.registrar,
            'created': str(w.creation_date),
            'expires': str(w.expiration_date),
            'name_servers': w.name_servers,
            'owner': w.name
        }
    except:
        print("    ❌ Ошибка получения WHOIS.")
    
    # ---- 2. DNS-записи ----
    print("\n[🌐] DNS-ЗАПИСИ:")
    try:
        for record_type in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    print(f"    {record_type}: {rdata}")
                    results['dns'] = results.get('dns', {})
                    results['dns'][record_type] = str(rdata)
            except:
                pass
    except:
        print("    ❌ Ошибка DNS-запросов.")
    
    # ---- 3. Поддомены ----
    print("\n[🔍] ПОДДОМЕНЫ (crt.sh):")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data[:20]:
                if 'name_value' in entry:
                    subdomains.add(entry['name_value'].lower())
            if subdomains:
                for sub in sorted(subdomains)[:10]:
                    print(f"    - {sub}")
                results['subdomains'] = list(subdomains)[:20]
                results['subdomains_url'] = url
            else:
                print("    ❌ Поддоменов не найдено.")
    except:
        print("    ❌ Ошибка поиска поддоменов.")
    
    # ---- 4. История ----
    print("\n[📜] ИСТОРИЯ (archive.org):")
    url = f"https://archive.org/wayback/available?url={domain}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if 'archived_snapshots' in data and data['archived_snapshots']:
                snap = data['archived_snapshots']['closest']
                print(f"    ✅ Последний снимок: {snap.get('url', 'Неизвестно')}")
                print(f"    Дата: {snap.get('timestamp', 'Неизвестно')}")
                results['archive'] = snap
            else:
                print("    ❌ История не найдена.")
    except:
        print("    ❌ Ошибка проверки истории.")
    
    save_to_cache(f"domain_{domain}", results)
    save_to_db('domains', ['domain', 'data', 'source'], [domain, json.dumps(results), 'FullRecon'])
    print("\n" + "═" * 70)

# ============================================
# 6. ПОИСК ПО ИМЕНИ И ФАМИЛИИ
# ============================================
def search_name_full(name):
    print(f"\n[👨] ПОИСК ПО ИМЕНИ: {name}\n")
    print("═" * 70)
    
    query = name.replace(' ', '+')
    results = {}
    
    print("\n[🔍] GOOGLE:")
    url = f"https://www.google.com/search?q={query}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            titles = soup.find_all('h3')
            if titles:
                for h in titles[:5]:
                    print(f"    - {h.text.strip()}")
                results['google'] = url
            else:
                print("    ❌ Ничего не найдено")
    except:
        print("    ❌ Ошибка")
    
    print("\n[🔍] LINKEDIN:")
    url = f"https://www.google.com/search?q={query}+site:linkedin.com"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            titles = soup.find_all('h3')
            if titles:
                for h in titles[:3]:
                    print(f"    - {h.text.strip()}")
                results['linkedin'] = url
            else:
                print("    ❌ Не найдено")
    except:
        print("    ❌ Ошибка")
    
    print("\n[🔍] FACEBOOK:")
    url = f"https://www.google.com/search?q={query}+site:facebook.com"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            titles = soup.find_all('h3')
            if titles:
                for h in titles[:3]:
                    print(f"    - {h.text.strip()}")
                results['facebook'] = url
            else:
                print("    ❌ Не найдено")
    except:
        print("    ❌ Ошибка")
    
    print("\n[🔍] VKONTAKTE:")
    url = f"https://www.google.com/search?q={query}+site:vk.com"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            titles = soup.find_all('h3')
            if titles:
                for h in titles[:3]:
                    print(f"    - {h.text.strip()}")
                results['vk'] = url
            else:
                print("    ❌ Не найдено")
    except:
        print("    ❌ Ошибка")
    
    print("\n[🔍] INSTAGRAM:")
    url = f"https://www.google.com/search?q={query}+site:instagram.com"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            titles = soup.find_all('h3')
            if titles:
                for h in titles[:3]:
                    print(f"    - {h.text.strip()}")
                results['instagram'] = url
            else:
                print("    ❌ Не найдено")
    except:
        print("    ❌ Ошибка")
    
    save_to_cache(f"name_{name}", results)
    print("\n" + "═" * 70)

# ============================================
# 7. ГЕНЕРАЦИЯ ОТЧЁТА
# ============================================
def generate_report(target, target_type):
    print(f"\n[📊] ГЕНЕРАЦИЯ ОТЧЁТА ПО: {target}\n")
    
    filename = f"report_{target}_{int(time.time())}.html"
    
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>ReconSniper Report</title>
<style>
body {{ font-family: Arial; background: #0a0a0a; color: #00ff00; padding: 20px; }}
h1 {{ color: #00ff00; border-bottom: 1px solid #00ff00; }}
h2 {{ color: #00cc00; }}
a {{ color: #00ff00; }}
.highlight {{ background: #001a00; padding: 10px; border-radius: 5px; }}
pre {{ background: #000000; padding: 10px; overflow: auto; }}
</style>
</head>
<body>
    <h1>🔍 ReconSniper v5.0 — Отчёт</h1>
    <p><strong>Цель:</strong> {target}</p>
    <p><strong>Тип:</strong> {target_type}</p>
    <p><strong>Дата:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <hr>
"""
    
    cached = get_from_cache(f"{target_type}_{target}")
    if cached:
        html += f"<h2>📁 Найденные ссылки</h2><div class='highlight'><ul>"
        for k, v in cached.items():
            if isinstance(v, str) and v.startswith('http'):
                html += f"<li><a href='{v}' target='_blank'>{k}: {v}</a></li>"
            elif isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    if isinstance(sub_v, str) and sub_v.startswith('http'):
                        html += f"<li><a href='{sub_v}' target='_blank'>{k}.{sub_k}: {sub_v}</a></li>"
        html += "</ul></div>"
    
    html += """
    <hr>
    <p>Отчёт создан ReconSniper v5.0 — Developer: @remeronoff</p>
</body>
</html>
"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] Отчёт сохранён: {filename}")
    print(f"[+] Открой в браузере: file://{os.path.abspath(filename)}")

# ============================================
# 8. УПРАВЛЕНИЕ БАЗАМИ ДАННЫХ
# ============================================
def manage_databases():
    print("\n[🗄️] УПРАВЛЕНИЕ БАЗАМИ ДАННЫХ\n")
    print("═" * 50)
    print("[1] Загрузить базу из файла (CSV/JSON/TXT)")
    print("[2] Показать статистику базы")
    print("[3] Очистить кэш")
    print("[0] Назад")
    print("═" * 50)
    
    choice = input("[?] > ").strip()
    
    if choice == "1":
        filepath = input("[?] Путь к файлу: ").strip()
        if os.path.exists(filepath):
            ext = filepath.split('.')[-1].lower()
            count = 0
            try:
                if ext == 'csv':
                    import csv
                    with open(filepath, 'r', encoding='utf-8') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if len(row) >= 1:
                                phone = row[0].strip()
                                name = row[1].strip() if len(row) > 1 else ''
                                save_to_db('phones', ['phone', 'name', 'source', 'data'],
                                           [phone, name, 'CSV', json.dumps(row)])
                                count += 1
                elif ext == 'json':
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                if 'phone' in item:
                                    save_to_db('phones', ['phone', 'name', 'source', 'data'],
                                               [item['phone'], item.get('name', ''), 'JSON', json.dumps(item)])
                                    count += 1
                        elif isinstance(data, dict):
                            for phone, info in data.items():
                                save_to_db('phones', ['phone', 'name', 'source', 'data'],
                                           [phone, info.get('name', ''), 'JSON', json.dumps(info)])
                                count += 1
                elif ext == 'txt':
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                parts = line.split('\t')
                                if len(parts) >= 1:
                                    phone = parts[0].strip()
                                    name = parts[1].strip() if len(parts) > 1 else ''
                                    save_to_db('phones', ['phone', 'name', 'source', 'data'],
                                               [phone, name, 'TXT', json.dumps(parts)])
                                    count += 1
                print(f"[+] Загружено записей: {count}")
            except Exception as e:
                print(f"[-] Ошибка: {e}")
        else:
            print("[-] Файл не найден.")
    
    elif choice == "2":
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        tables = ['phones', 'emails', 'usernames', 'ips', 'domains', 'cache']
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"    {table}: {count} записей")
        conn.close()
    
    elif choice == "3":
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cache")
        conn.commit()
        conn.close()
        print("[+] Кэш очищен.")
    
    input("[!] Нажмите Enter...")

# ============================================
# ГЛАВНОЕ МЕНЮ
# ============================================
def menu():
    banner()

def main():
    init_db()
    
    while True:
        menu()
        choice = input("[?] Выберите действие: ").strip()
        
        if choice == "1":
            phone = input("[?] Номер телефона (+7XXXXXXXXXX): ").strip()
            if phone:
                search_phone_full(phone)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "2":
            email = input("[?] Email: ").strip()
            if email:
                search_email_full(email)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "3":
            username = input("[?] Никнейм: ").strip()
            if username:
                search_username_full(username)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "4":
            ip = input("[?] IP-адрес: ").strip()
            if ip:
                search_ip_full(ip)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "5":
            domain = input("[?] Домен: ").strip()
            if domain:
                search_domain_full(domain)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "6":
            name = input("[?] Имя и фамилия: ").strip()
            if name:
                search_name_full(name)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "7":
            manage_databases()
            
        elif choice == "8":
            target = input("[?] Цель для отчёта: ").strip()
            target_type = input("[?] Тип (phone/email/username/ip/domain/name): ").strip()
            if target and target_type:
                generate_report(target, target_type)
            input("\n[!] Нажмите Enter...")
            
        elif choice == "0":
            print("[+] Выход...")
            sys.exit(0)
        else:
            print("[-] Неверный выбор!")
            time.sleep(1)

if __name__ == "__main__":
    main()
