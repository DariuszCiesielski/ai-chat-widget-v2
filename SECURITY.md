# 🔒 Bezpieczeństwo AI Chat Widget

Ten dokument opisuje zagrożenia bezpieczeństwa oraz zalecane środki ochrony.

## ⚠️ Zagrożenia

### 1. XSS (Cross-Site Scripting) - KRYTYCZNE 🔴

**Zagrożenie:**
Widget używa `innerHTML` do wyświetlania wiadomości, co pozwala na wykonanie kodu JavaScript, jeśli AI zwróci złośliwy kod.

```javascript
// NIEBEZPIECZNY KOD (obecna wersja):
content.innerHTML = formatMessage(text);
```

**Przykład ataku:**
```json
{
  "output": "<img src=x onerror='alert(document.cookie)'>"
}
```

**Skutki:**
- Kradzież cookies i session storage
- Wykonanie złośliwego kodu JavaScript
- Przekierowanie użytkownika na phishing
- Modyfikacja DOM strony
- Kradzież tokenów i danych

**ROZWIĄZANIE: Sanityzacja HTML**

Użyj biblioteki DOMPurify lub sanityzuj ręcznie:

```javascript
// Opcja 1: DOMPurify (zalecane)
function formatMessage(text) {
    const formatted = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/\n/g, '<br>');

    return DOMPurify.sanitize(formatted);
}

// Opcja 2: textContent (najprostsze, ale traci formatowanie)
content.textContent = text;

// Opcja 3: Escape HTML ręcznie
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
```

**Dodaj DOMPurify:**
```html
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>
```

---

### 2. Brak Rate Limiting - WYSOKIE 🟡

**Zagrożenie:**
Brak ograniczeń pozwala na spam i abuse, co prowadzi do:
- Wysokich kosztów API
- Przeciążenia serwera n8n
- DoS attack

**ROZWIĄZANIE: Rate Limiting po stronie klienta**

```javascript
// Dodaj do widgetu:
const RATE_LIMIT = {
    maxMessages: 10,           // Max wiadomości
    timeWindow: 60000,         // w ciągu 60 sekund
    cooldown: 2000             // 2 sekundy między wiadomościami
};

let messageTimestamps = [];
let lastMessageTime = 0;

function checkRateLimit() {
    const now = Date.now();

    // Cooldown między wiadomościami
    if (now - lastMessageTime < RATE_LIMIT.cooldown) {
        showError('Poczekaj chwilę przed wysłaniem kolejnej wiadomości.');
        return false;
    }

    // Usuń stare timestamps
    messageTimestamps = messageTimestamps.filter(
        time => now - time < RATE_LIMIT.timeWindow
    );

    // Sprawdź limit
    if (messageTimestamps.length >= RATE_LIMIT.maxMessages) {
        showError('Przekroczono limit wiadomości. Spróbuj za minutę.');
        return false;
    }

    messageTimestamps.push(now);
    lastMessageTime = now;
    return true;
}

// W funkcji sendMessage():
async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    // Sprawdź rate limit
    if (!checkRateLimit()) {
        return;
    }

    // ... reszta kodu
}
```

**ROZWIĄZANIE: Rate Limiting w n8n**

Dodaj node "Code" przed AI node:

```javascript
// Rate Limiting w n8n
const sessionId = $input.item.json.sessionId;
const now = Date.now();

// Pobierz historię z cache/Redis/database
const history = await getSessionHistory(sessionId);

// Sprawdź liczbę wiadomości w ostatniej minucie
const recentMessages = history.filter(
    msg => now - msg.timestamp < 60000
);

if (recentMessages.length > 10) {
    throw new Error('Rate limit exceeded');
}

// Zapisz timestamp
await saveMessageTimestamp(sessionId, now);

return $input.all();
```

---

### 3. Publiczny Webhook - WYSOKIE 🟡

**Zagrożenie:**
URL webhooka jest widoczny w kodzie źródłowym, każdy może go użyć.

**ROZWIĄZANIA:**

#### A. Autentykacja API Key

**W widgecie:**
```javascript
const CONFIG = {
    webhookUrl: 'https://n8n.aimarketingmasters.pl/webhook/...',
    apiKey: 'YOUR_SECRET_API_KEY', // Przechowuj bezpiecznie!
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'YOUR_SECRET_API_KEY'
    }
};
```

**W n8n (pierwszy node - IF):**
```javascript
// Sprawdź API key
const apiKey = $input.item.json.headers['x-api-key'];
const validKey = 'YOUR_SECRET_API_KEY';

if (apiKey !== validKey) {
    throw new Error('Unauthorized');
}

return $input.all();
```

**UWAGA:** API key nadal jest widoczny w kodzie! Lepsze rozwiązanie poniżej.

#### B. Backend Proxy (ZALECANE)

**Architektura:**
```
Widget → Twój Backend (PHP/Node) → n8n Webhook
         (z API key)
```

**Korzyści:**
- API key ukryty na serwerze
- Dodatkowa walidacja
- Lepsze logowanie
- Więcej kontroli

**Przykład (Node.js/Express):**
```javascript
// server.js
const express = require('express');
const axios = require('axios');

app.post('/api/chat', async (req, res) => {
    // Walidacja po stronie serwera
    const { message, sessionId } = req.body;

    if (!message || message.length > 1000) {
        return res.status(400).json({ error: 'Invalid message' });
    }

    // Wysyłka do n8n z ukrytym API key
    const response = await axios.post(
        process.env.N8N_WEBHOOK_URL,
        { message, sessionId },
        {
            headers: {
                'X-API-Key': process.env.N8N_API_KEY
            }
        }
    );

    res.json(response.data);
});
```

**W widgecie zmień:**
```javascript
webhookUrl: '/api/chat' // Zamiast bezpośrednio do n8n
```

#### C. CORS - Ogranicz domeny

**W n8n node "Respond to Webhook":**
```javascript
{
  "Access-Control-Allow-Origin": "https://twoja-domena.pl", // NIE "*"
  "Access-Control-Allow-Methods": "POST",
  "Access-Control-Allow-Headers": "Content-Type"
}
```

#### D. Webhook signing/HMAC

```javascript
// Widget generuje podpis
const timestamp = Date.now();
const signature = await generateHMAC(message + timestamp, SECRET);

// Wysyłka
{
    message: message,
    timestamp: timestamp,
    signature: signature
}

// n8n weryfikuje podpis
const isValid = verifyHMAC(message, timestamp, signature, SECRET);
```

---

### 4. Brak Walidacji Inputu - ŚREDNIE 🟡

**ROZWIĄZANIE: Walidacja długości**

```javascript
const MAX_MESSAGE_LENGTH = 1000;

async function sendMessage() {
    const message = chatInput.value.trim();

    if (!message) return;

    // Walidacja długości
    if (message.length > MAX_MESSAGE_LENGTH) {
        showError(`Wiadomość za długa (max ${MAX_MESSAGE_LENGTH} znaków)`);
        return;
    }

    // Walidacja znaków (opcjonalne)
    if (!/^[\s\S]*$/.test(message)) {
        showError('Wiadomość zawiera niedozwolone znaki');
        return;
    }

    // ... reszta kodu
}
```

---

### 5. Session Hijacking - NISKIE 🟢

**ROZWIĄZANIE: Lepsze generowanie Session ID**

```javascript
// Użyj crypto.randomUUID() (nowoczesne przeglądarki)
function getSessionId() {
    let sessionId = sessionStorage.getItem('chatSessionId');
    if (!sessionId) {
        // Lepsze generowanie ID
        if (crypto.randomUUID) {
            sessionId = crypto.randomUUID();
        } else {
            // Fallback dla starszych przeglądarek
            sessionId = 'session_' + Date.now() + '_' +
                        Math.random().toString(36).substring(2) +
                        Math.random().toString(36).substring(2);
        }
        sessionStorage.setItem('chatSessionId', sessionId);
    }
    return sessionId;
}
```

---

### 6. SQL Injection (jeśli używasz bazy danych)

**Zagrożenie:**
Jeśli w n8n zapisujesz wiadomości do bazy danych bez sanityzacji.

**ROZWIĄZANIE:**
- Używaj **prepared statements**
- Nie konkatenuj SQL queries
- Używaj ORM (Prisma, TypeORM)

**Źle:**
```javascript
const query = `INSERT INTO messages VALUES ('${message}')`;
```

**Dobrze:**
```javascript
const query = 'INSERT INTO messages VALUES (?)';
db.execute(query, [message]);
```

---

### 7. Logs i Monitoring

**ROZWIĄZANIE: Nie loguj wrażliwych danych**

```javascript
// ❌ ŹLE
console.log('User message:', message, 'API Key:', apiKey);

// ✅ DOBRZE
console.log('User message sent, sessionId:', sessionId);
```

**W n8n:**
- Nie loguj pełnych wiadomości
- Maskuj wrażliwe dane
- Regularnie przeglądaj logi

---

## 🛡️ Checklist Bezpieczeństwa

Przed wdrożeniem produkcyjnym:

### Frontend (Widget)
- [ ] Sanityzacja HTML (DOMPurify)
- [ ] Rate limiting po stronie klienta
- [ ] Walidacja długości wiadomości
- [ ] Lepsze generowanie Session ID
- [ ] HTTPS only (nie HTTP)
- [ ] CSP headers
- [ ] Usuń console.log z produkcji

### Backend (n8n)
- [ ] Rate limiting w n8n
- [ ] Autentykacja (API key/HMAC)
- [ ] CORS - tylko Twoja domena
- [ ] Walidacja wszystkich inputów
- [ ] Timeout na requesty
- [ ] Monitoring i alerty
- [ ] Error handling (nie ujawniaj stack traces)

### Infrastructure
- [ ] HTTPS z ważnym certyfikatem
- [ ] Firewall (IP whitelisting jeśli możliwe)
- [ ] DDoS protection (Cloudflare)
- [ ] Backup danych
- [ ] Regularne aktualizacje
- [ ] Monitoring kosztów API

### Prywatność (RODO)
- [ ] Polityka prywatności
- [ ] Zgoda użytkownika
- [ ] Informacja o przetwarzaniu danych
- [ ] Możliwość usunięcia danych
- [ ] Szyfrowanie danych wrażliwych
- [ ] Audyt zgodności z RODO

---

## 🚨 Co zrobić w przypadku ataku?

1. **Natychmiast:**
   - Wyłącz webhook w n8n
   - Zmień API keys
   - Sprawdź logi

2. **Analiza:**
   - Zidentyfikuj źródło ataku
   - Oceń szkody
   - Sprawdź, czy dane wyciekły

3. **Naprawa:**
   - Załataj luki
   - Wdróż dodatkowe zabezpieczenia
   - Przetestuj

4. **Komunikacja:**
   - Poinformuj użytkowników (jeśli RODO wymaga)
   - Zgłoś incydent do UODO (jeśli konieczne)

---

## 📚 Dodatkowe Zasoby

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DOMPurify Documentation](https://github.com/cure53/DOMPurify)
- [n8n Security Best Practices](https://docs.n8n.io/hosting/security/)
- [RODO - UODO](https://uodo.gov.pl/)

---

## ⚖️ Disclaimer

Ten widget jest dostarczany "as is" bez gwarancji. Użytkownik ponosi pełną odpowiedzialność za bezpieczeństwo swojej implementacji. Zalecamy profesjonalny audyt bezpieczeństwa przed wdrożeniem produkcyjnym.
