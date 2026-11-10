import json

identity = json.loads(r"""$build_dedup_identity.message""")
response = json.loads(r"""$check_duplicate_alert""")

if str(response.get("status")) != "200":
    raise ValueError(
        "Recherche TheHive en erreur : " + str(response.get("status"))
    )

alerts = response.get("body")
if isinstance(alerts, str):
    alerts = json.loads(alerts)

if not isinstance(alerts, list):
    raise ValueError("Liste d'alertes TheHive attendue")

def fields(alert):
    values = alert.get("customFields") or []
    if not isinstance(values, list):
        raise ValueError(
            "Format customFields inattendu : liste name/value attendue"
        )
    return values

exact = [
    alert for alert in alerts
    if alert.get("sourceRef") == identity["source_ref"]
    or identity["event_tag"] in (alert.get("tags") or [])
]

if len(exact) > 1:
    raise ValueError("Plusieurs alertes contiennent le meme evenement")

if exact:
    result = {
        "action": "skip",
        "target_alert_id": exact[0]["_id"],
    }

else:
    active = []

    for alert in alerts:
        if not identity["group_tag"]:
            continue
        if identity["group_tag"] not in (alert.get("tags") or []):
            continue

        last_seen = next((
            field["value"]
            for field in fields(alert)
            if field.get("name") == "wazuh-last-seen"
        ), None)

        if type(last_seen) is not int:
            raise ValueError("wazuh-last-seen absent ou invalide")

        if last_seen > identity["received_ms"]:
            raise ValueError("Date du groupe situee dans le futur")

        if last_seen >= identity["cutoff_ms"]:
            active.append(alert)

    if len(active) > 1:
        raise ValueError("Plusieurs groupes actifs pour cette empreinte")

    target = active[0] if active else None

    custom_fields = [
        {"name": field["name"], "value": field["value"]}
        for field in fields(target)
        if field["name"] != "wazuh-last-seen"
    ] if target else []

    custom_fields.append({
        "name": "wazuh-last-seen",
        "value": identity["received_ms"],
    })

    tags = [identity["event_tag"]]
    if identity["group_tag"]:
        tags.append(identity["group_tag"])

    result = {
        "action": "update" if target else "create",
        "target_alert_id": target["_id"] if target else None,
        "source_ref": identity["source_ref"],
        "metadata": {
            "tags": tags,
            "customFields": custom_fields,
        },
    }

print(json.dumps(result))