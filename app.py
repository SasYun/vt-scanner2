import streamlit as st
import requests
import time
import csv
import base64
import io

# --- ФУНКЦІЇ ЛОГІКИ ---
def force_scan(url, api_key):
    headers = {"x-apikey": api_key}
    try:
        requests.post("https://www.virustotal.com/api/v3/urls", data={'url': url}, headers=headers, timeout=10)
    except: pass

def get_actual_data(url, api_key):
    u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=").strip()
    headers = {"x-apikey": api_key}
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers=headers, timeout=10)
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']['malicious']
    except: pass
    return 0

# --- ІНТЕРФЕЙС STREAMLIT ---
st.set_page_config(page_title="Domain Audit Tool", page_icon="🛡️")

st.title("🛡️ Domain Security Audit")
st.markdown("Перевірка доменів через VirusTotal API (Nocache mode) для Confluence.")

# Поля вводу
api_key = st.text_input("Введіть свій VirusTotal API Key", type="password", help="Отримати ключ можна на сайті virustotal.com")
domains_input = st.text_area("Список доменів (кожен з нового рядка)", height=200, placeholder="example.com\ntest-site.net")

if st.button("🚀 Запустити сканування"):
    if not api_key:
        st.error("Помилка: Ви не ввели API Key!")
    elif not domains_input:
        st.error("Помилка: Список доменів порожній!")
    else:
        domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
        routes = ['', 'tds', 'tds/rsl', 'arb']
        
        # Етап 1: Force Scan
        st.info(f"🔍 Етап 1: Оновлюємо кеш для {len(domains)} доменів...")
        scan_progress = st.progress(0)
        for i, domain in enumerate(domains):
            for r in routes:
                path = f"/{r}" if r else "/"
                force_scan(f"http://{domain}{path}", api_key)
                force_scan(f"https://{domain}{path}", api_key)
                time.sleep(0.5) # Швидкий прогрів
            scan_progress.progress((i + 1) / len(domains))
        
        # Пауза
        st.warning("⏳ Чекаємо 120 секунд, поки VirusTotal оновить звіти...")
        time.sleep(120)
        
        # Етап 2: Збір даних
        st.info("📊 Етап 2: Збір результатів...")
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Domain', 'Path & Score'])
        
        # Створюємо порожню таблицю в інтерфейсі для динамічного оновлення
        results_table = st.empty()
        display_data = []

        for domain in domains:
            for idx, r in enumerate(routes):
                path = f"/{r}" if r else "/"
                s_http = get_actual_data(f"http://{domain}{path}", api_key)
                time.sleep(16) # Пауза для безкоштовного ключа
                s_https = get_actual_data(f"https://{domain}{path}", api_key)
                time.sleep(16)
                
                domain_col = domain if idx == 0 else ""
                row_text = f"{path} {s_http}+{s_https}"
                
                # Запис у CSV
                writer.writerow([domain_col, row_text])
                
                # Додавання в таблицю на екрані
                display_data.append({"Домен": domain_col, "Роут та результат": row_text})
                results_table.table(display_data)
        
        st.success("✅ Сканування завершено!")
        
        # Кнопка завантаження
        st.download_button(
            label="📥 Завантажити CSV для Confluence",
            data=output.getvalue(),
            file_name="audit_results.csv",
            mime="text/csv"
        )