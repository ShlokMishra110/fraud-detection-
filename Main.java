import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

public class Main {

    // ---------- Model ----------
    static class Transaction {
        String id, accountId, location;
        double amount;
        LocalDateTime time;
        Transaction(String id, String accountId, double amount, String location, LocalDateTime time) {
            this.id = id; this.accountId = accountId; this.amount = amount;
            this.location = location; this.time = time;
        }
    }

    // ---------- Rules ----------
    interface FraudRule {
        String check(Transaction t, List<Transaction> history); // null = clean
    }

    static class HighAmountRule implements FraudRule {
        double limit;
        HighAmountRule(double limit) { this.limit = limit; }
        public String check(Transaction t, List<Transaction> h) {
            return t.amount > limit ? "High amount: exceeds " + (long) limit : null;
        }
    }

    static class RapidTransactionRule implements FraudRule {
        public String check(Transaction t, List<Transaction> h) {
            long recent = h.stream()
                .filter(x -> Math.abs(Duration.between(x.time, t.time).toMinutes()) <= 5)
                .count();
            return recent >= 3 ? "Rapid transactions: 3+ within 5 minutes" : null;
        }
    }

    static class LocationChangeRule implements FraudRule {
        public String check(Transaction t, List<Transaction> h) {
            if (h.isEmpty()) return null;
            Transaction last = h.get(h.size() - 1);
            boolean moved = !last.location.equalsIgnoreCase(t.location);
            boolean fast = Math.abs(Duration.between(last.time, t.time).toHours()) < 1;
            return (moved && fast) ? "Location changed within 1 hour" : null;
        }
    }

    static class ZScoreRule implements FraudRule {
        public String check(Transaction t, List<Transaction> h) {
            if (h.size() < 5) return null;
            double mean = h.stream().mapToDouble(x -> x.amount).average().orElse(0);
            double var = h.stream().mapToDouble(x -> Math.pow(x.amount - mean, 2)).average().orElse(0);
            double sd = Math.sqrt(var);
            if (sd == 0) return null;
            double z = (t.amount - mean) / sd;
            return z > 3 ? String.format("Unusual amount for this account (z=%.1f)", z) : null;
        }
    }

    // ---------- Engine ----------
    static class FraudEngine {
        List<FraudRule> rules = new ArrayList<>();
        Map<String, List<Transaction>> history = new HashMap<>();

        FraudEngine() {
            rules.add(new HighAmountRule(50000));
            rules.add(new RapidTransactionRule());
            rules.add(new LocationChangeRule());
            rules.add(new ZScoreRule());
        }

        List<String> process(Transaction t) {
            List<Transaction> h = history.computeIfAbsent(t.accountId, k -> new ArrayList<>());
            List<String> flags = new ArrayList<>();
            for (FraudRule r : rules) {
                String res = r.check(t, h);
                if (res != null) flags.add(res);
            }
            h.add(t);
            return flags;
        }
    }

    static FraudEngine engine = new FraudEngine();
    static int counter = 0;

    // ---------- Web helpers ----------
    static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    static Map<String, String> parse(String body) {
        Map<String, String> m = new HashMap<>();
        for (String kv : body.split("&")) {
            String[] p = kv.split("=", 2);
            if (p.length == 2)
                m.put(URLDecoder.decode(p[0], StandardCharsets.UTF_8),
                      URLDecoder.decode(p[1], StandardCharsets.UTF_8));
        }
        return m;
    }

    static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ---------- Main ----------
    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/", ex -> send(ex, 200, "text/html; charset=utf-8", PAGE));

        server.createContext("/analyze", ex -> {
            try {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> f = parse(body);
                String account = f.getOrDefault("account", "").trim();
                String location = f.getOrDefault("location", "").trim();
                double amount = Double.parseDouble(f.getOrDefault("amount", ""));
                String ts = f.getOrDefault("time", "").trim();
                LocalDateTime time = ts.isEmpty() ? LocalDateTime.now().withNano(0) : LocalDateTime.parse(ts);
                if (account.isEmpty() || location.isEmpty() || amount < 0)
                    throw new IllegalArgumentException("bad input");

                List<String> flags;
                String id;
                synchronized (Main.class) {
                    id = "T" + (++counter);
                    flags = engine.process(new Transaction(id, account, amount, location, time));
                }
                String risk = flags.isEmpty() ? "LOW" : (flags.size() == 1 ? "MEDIUM" : "HIGH");

                StringBuilder sb = new StringBuilder();
                sb.append("{\"id\":\"").append(id).append("\",")
                  .append("\"account\":\"").append(esc(account)).append("\",")
                  .append("\"amount\":").append(amount).append(",")
                  .append("\"location\":\"").append(esc(location)).append("\",")
                  .append("\"time\":\"").append(time).append("\",")
                  .append("\"risk\":\"").append(risk).append("\",\"flags\":[");
                for (int i = 0; i < flags.size(); i++) {
                    if (i > 0) sb.append(",");
                    sb.append("\"").append(esc(flags.get(i))).append("\"");
                }
                sb.append("]}");
                send(ex, 200, "application/json", sb.toString());
            } catch (Exception e) {
                send(ex, 400, "application/json", "{\"error\":\"Invalid input\"}");
            }
        });

        server.createContext("/reset", ex -> {
            synchronized (Main.class) { engine = new FraudEngine(); counter = 0; }
            send(ex, 200, "application/json", "{\"ok\":true}");
        });

        server.start();
        System.out.println("Fraud Detection server running on http://localhost:" + port);
    }

    // ---------- Web page ----------
    static final String PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Financial Fraud Detection</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f3f5f9; color: #1d2433; }
  header { background: #1f3a68; color: #fff; padding: 18px 28px; }
  header h1 { margin: 0; font-size: 22px; }
  header p { margin: 4px 0 0; font-size: 13px; opacity: .8; }
  main { max-width: 1000px; margin: 22px auto; padding: 0 16px; }
  .card { background: #fff; border-radius: 10px; padding: 18px; margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }
  label { font-size: 12px; font-weight: 600; color: #50607a; display: block; margin-bottom: 4px; }
  input { width: 100%; padding: 9px; border: 1px solid #c8d0de; border-radius: 6px; font-size: 14px; }
  .btns { margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }
  button { padding: 10px 18px; border: 0; border-radius: 6px; font-size: 14px; cursor: pointer; font-weight: 600; }
  .primary { background: #1f3a68; color: #fff; }
  .secondary { background: #e3e8f2; color: #1f3a68; }
  .danger { background: #fbe4e4; color: #a12626; }
  .stats { display: flex; gap: 12px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 130px; border-radius: 8px; padding: 12px; text-align: center; background: #eef2f9; }
  .stat b { display: block; font-size: 26px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; background: #eef2f9; padding: 9px; font-size: 12px; color: #50607a; }
  td { padding: 9px; border-bottom: 1px solid #edf0f6; vertical-align: top; }
  .badge { padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 700; }
  .LOW { background: #dff5e3; color: #1b7a34; }
  .MEDIUM { background: #fff0cc; color: #8a6200; }
  .HIGH { background: #fbdcdc; color: #b11d1d; }
  .flag { display: block; font-size: 12px; color: #6b2a2a; }
  #msg { color: #b11d1d; font-size: 13px; margin-top: 8px; min-height: 16px; }
  small { color: #6b778c; }
</style>
</head>
<body>
<header>
  <h1>Financial Fraud Detection System</h1>
  <p>Java rule-based engine: high amount, rapid transactions, location change, statistical anomaly (z-score)</p>
</header>
<main>
  <div class="card">
    <div class="grid">
      <div><label>Account ID</label><input id="account" placeholder="e.g. A1" value="A1"></div>
      <div><label>Amount (INR)</label><input id="amount" type="number" min="0" placeholder="e.g. 2500"></div>
      <div><label>Location</label><input id="location" placeholder="e.g. Mumbai"></div>
      <div><label>Date and time</label><input id="time" type="datetime-local"></div>
    </div>
    <div class="btns">
      <button class="primary" onclick="addTx()">Analyze transaction</button>
      <button class="secondary" onclick="loadDemo()">Load demo data</button>
      <button class="danger" onclick="resetAll()">Reset</button>
    </div>
    <div id="msg"></div>
    <small>Tip: the z-score rule needs at least 5 earlier transactions on the same account.</small>
  </div>

  <div class="card">
    <div class="stats">
      <div class="stat"><b id="sTotal">0</b>Total</div>
      <div class="stat"><b id="sLow">0</b>Low risk</div>
      <div class="stat"><b id="sMed">0</b>Medium risk</div>
      <div class="stat"><b id="sHigh">0</b>High risk</div>
    </div>
  </div>

  <div class="card">
    <table>
      <thead><tr><th>ID</th><th>Account</th><th>Amount</th><th>Location</th><th>Time</th><th>Risk</th><th>Reasons</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</main>

<script>
  let counts = { total: 0, LOW: 0, MEDIUM: 0, HIGH: 0 };

  async function submitTx(account, amount, location, time) {
    const body = new URLSearchParams({ account: account, amount: amount, location: location, time: time });
    const r = await fetch('/analyze', { method: 'POST', body: body });
    if (!r.ok) throw new Error('Invalid input');
    return r.json();
  }

  function addRow(d) {
    const tr = document.createElement('tr');
    const reasons = d.flags.length ? d.flags.map(f => '<span class="flag">' + f + '</span>').join('') : '-';
    tr.innerHTML =
      '<td>' + d.id + '</td><td>' + d.account + '</td><td>' + Number(d.amount).toLocaleString() + '</td>' +
      '<td>' + d.location + '</td><td>' + d.time.replace('T', ' ') + '</td>' +
      '<td><span class="badge ' + d.risk + '">' + d.risk + '</span></td><td>' + reasons + '</td>';
    document.getElementById('rows').prepend(tr);
    counts.total++; counts[d.risk]++;
    document.getElementById('sTotal').textContent = counts.total;
    document.getElementById('sLow').textContent = counts.LOW;
    document.getElementById('sMed').textContent = counts.MEDIUM;
    document.getElementById('sHigh').textContent = counts.HIGH;
  }

  async function addTx() {
    const msg = document.getElementById('msg');
    msg.textContent = '';
    const account = document.getElementById('account').value;
    const amount = document.getElementById('amount').value;
    const location = document.getElementById('location').value;
    const time = document.getElementById('time').value;
    if (!account || !amount || !location) { msg.textContent = 'Please fill account, amount and location.'; return; }
    try { addRow(await submitTx(account, amount, location, time)); }
    catch (e) { msg.textContent = 'Could not analyze: check your inputs.'; }
  }

  async function loadDemo() {
    const demo = [
      ['A1', 500, 'Mumbai', '2026-10-17T10:00'],
      ['A1', 450, 'Mumbai', '2026-10-17T10:30'],
      ['A1', 520, 'Mumbai', '2026-10-17T11:00'],
      ['A1', 480, 'Mumbai', '2026-10-17T11:30'],
      ['A1', 510, 'Mumbai', '2026-10-17T12:00'],
      ['A1', 90000, 'Delhi', '2026-10-17T12:20']
    ];
    for (const d of demo) addRow(await submitTx(d[0], d[1], d[2], d[3]));
  }

  async function resetAll() {
    await fetch('/reset');
    document.getElementById('rows').innerHTML = '';
    counts = { total: 0, LOW: 0, MEDIUM: 0, HIGH: 0 };
    ['sTotal', 'sLow', 'sMed', 'sHigh'].forEach(id => document.getElementById(id).textContent = 0);
  }
</script>
</body>
</html>
""";
}