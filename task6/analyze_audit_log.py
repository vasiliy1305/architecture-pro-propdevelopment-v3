#!/usr/bin/env python3
"""
Анализ Kubernetes audit.log для выявления подозрительных действий.
Версия: авторская переработка под Task6.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

SEV_ORDER = ["low", "medium", "high", "critical"]

# --------------------------- УТИЛИТЫ ---------------------------------

def dig(data, path, default=None):
    """Безопасное извлечение значения из вложенных словарей."""
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur

def to_utc(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except Exception:
        return ts

def each_event(src: Path):
    """Построчный разбор JSON Lines"""
    with src.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

# --------------------------- ДЕТЕКТОРЫ ---------------------------------

def detect_secret_read(ev):
    return dig(ev, "objectRef.resource") == "secrets" and dig(ev, "verb") in {"get", "list"}

def detect_priv_pod(ev):
    if dig(ev, "verb") != "create" or dig(ev, "objectRef.resource") != "pods":
        return False
    spec = dig(ev, "requestObject.spec") or {}
    for c in spec.get("containers", []):
        if dig(c, "securityContext.privileged") is True:
            return True
    return dig(spec, "securityContext.privileged") is True

def detect_exec_other(ev, home):
    if dig(ev, "verb") not in {"create", "patch"}:
        return False
    uri = dig(ev, "requestURI", "")
    ns = dig(ev, "objectRef.namespace")
    if "/exec" not in uri:
        return False
    if ns == "kube-system" or (home and ns and ns != home):
        return True
    return False

def detect_admin_bind(ev):
    if dig(ev, "verb") != "create":
        return False
    if dig(ev, "objectRef.resource") not in {"rolebindings", "clusterrolebindings"}:
        return False
    return dig(ev, "requestObject.roleRef.name") == "cluster-admin"

def detect_audit_remove(ev):
    if dig(ev, "verb") != "delete":
        return False
    txt = (dig(ev, "objectRef.name", "") + dig(ev, "requestURI", "")).lower()
    return "audit" in txt

# --------------------------- ОСНОВНОЙ АНАЛИЗ ---------------------------

def label_and_score(ev, home):
    tags, severity = [], "low"

    if detect_secret_read(ev):
        tags.append("secrets")
        severity = "medium"
    if detect_priv_pod(ev):
        tags.append("privileged-pod")
        severity = "high"
    if detect_exec_other(ev, home):
        tags.append("cross-exec")
        severity = "high"
    if detect_admin_bind(ev):
        tags.append("cluster-admin")
        severity = "critical"
    if detect_audit_remove(ev):
        tags.append("audit-policy-delete")
        severity = "critical"

    return severity, tags


def summarize_event(ev):
    return {
        "user": dig(ev, "user.username"),
        "verb": dig(ev, "verb"),
        "ns": dig(ev, "objectRef.namespace"),
        "resource": dig(ev, "objectRef.resource"),
        "name": dig(ev, "objectRef.name"),
        "uri": dig(ev, "requestURI"),
        "timestamp": to_utc(dig(ev, "requestReceivedTimestamp", "")),
    }

# --------------------------- ОТЧЁТ ------------------------------------

def make_report(events, stats, actors):
    lines = ["# Отчёт по результатам анализа Kubernetes Audit Log", ""]
    lines.append("## Подозрительные события\n")

    def find(tag):
        for e in events:
            if tag in e["tags"]:
                return e
        return None

    mapping = {
        "secrets": "1. Доступ к секретам",
        "privileged-pod": "2. Привилегированные поды",
        "cross-exec": "3. Использование kubectl exec в чужом поде",
        "cluster-admin": "4. Создание RoleBinding с правами cluster-admin",
        "audit-policy-delete": "5. Удаление audit-policy.yaml",
    }

    for tag, title in mapping.items():
        e = find(tag)
        lines.append(title + ":")
        if not e:
            lines.append("   - Не обнаружено.\n")
            continue
        user = e.get("user") or "неизвестно"
        lines.append(f"   - Кто: {user}")
        lines.append(f"   - Где: ns={e.get('ns') or '—'}, ресурс={e.get('resource')}, имя={e.get('name') or '—'}")
        if tag == "secrets":
            lines.append("   - Почему подозрительно: попытка чтения secrets.\n")
        elif tag == "privileged-pod":
            lines.append("   - Комментарий: создан под с privileged=true.\n")
        elif tag == "cross-exec":
            lines.append("   - Что делал: exec в чужом namespace.\n")
        elif tag == "cluster-admin":
            lines.append("   - К чему привело: эскалация привилегий.\n")
        elif tag == "audit-policy-delete":
            lines.append("   - Последствия: отключение аудита.\n")

    lines.append("## Вывод\n")
    lines.append(f"- Всего подозрительных событий: {len(events)}")
    lines.append(f"- Статистика: {json.dumps(stats, ensure_ascii=False)}")
    lines.append("- Основные ошибки RBAC: слишком широкие права на pods, secrets и RoleBinding.")

    if actors:
        lines.append("\n### Активность пользователей:")
        for u, c in sorted(actors.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"- {u}: {c}")

    return "\n".join(lines)

# --------------------------- MAIN -------------------------------------

def main():
    p = argparse.ArgumentParser(description="Kubernetes audit log analyzer")
    p.add_argument("--log", required=True, help="Файл audit.log (JSON lines)")
    p.add_argument("--out", default=".", help="Каталог вывода результатов")
    p.add_argument("--namespace", default="secure-ops", help="Домашний namespace пользователя")
    args = p.parse_args()

    path = Path(args.log)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    results, stats, actors = [], {"secrets":0,"privileged-pod":0,"cross-exec":0,"cluster-admin":0,"audit-policy-delete":0}, {}

    for ev in each_event(path):
        sev, tags = label_and_score(ev, args.namespace)
        if not tags:
            continue
        slim = summarize_event(ev)
        slim["severity"] = sev
        slim["tags"] = tags
        results.append(slim)
        for t in tags:
            stats[t] += 1
        user = slim.get("user") or "unknown"
        actors[user] = actors.get(user, 0) + 1

    # сохраняем JSON
    json_out = outdir / "audit-extract.json"
    json.dump({"events": results}, json_out.open("w", encoding="utf-8"), ensure_ascii=False, indent=2)

    # создаем Markdown
    report = make_report(results, stats, actors)
    (outdir / "analysis.md").write_text(report, encoding="utf-8")

    print(f"✅  Analysis complete: {json_out} and analysis.md written")

if __name__ == "__main__":
    main()
