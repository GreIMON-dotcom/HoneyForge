"""Upgrade of a two-slot installation: schema changes, and no telemetry or history is lost."""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from backend.app.lifecycle import pot_views
from backend.app.models import Honeypot
from backend.app.services import bootstrap

ROOT = Path(__file__).resolve().parents[1]
TWO_SLOT_REVISION = "c51aa2fc901d"
AT = "2026-10-10 12:00:00.000000"


def alembic(url, revision):
    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", revision], cwd=ROOT, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", env=os.environ | {"DATABASE_URL": url})
    assert result.returncode == 0, result.stdout + result.stderr


def seed_two_slot_installation(path):
    """Rows exactly as release 1.0 stored them, including a locally orchestrated third target."""
    tcp = {"name": "Lab TCP", "interaction_level": "low", "service_type": "tcp", "port": 8022, "banner": "SSH-2.0-Legacy",
           "memory_mb": 128, "cpu_limit": 0.5, "enabled": True}
    web = {"name": "Lab HTTP", "interaction_level": "medium", "service_type": "http", "port": 8080,
           "identity": "Старая панель", "memory_mb": 128, "cpu_limit": 0.5, "enabled": True}
    db = sqlite3.connect(path)
    db.execute("INSERT INTO users VALUES ('u1','admin','scrypt$00$00','administrator',1,?)", (AT,))
    for identifier, spec in (("p-tcp", tcp), ("p-web", web)):
        db.execute("INSERT INTO honeypot_profiles VALUES (?,?,?,3,?,?)", (identifier, spec["name"], json.dumps(spec), AT, AT))
    for host, service, provisioning in (("lab-low", "tcp", "compose"), ("lab-medium", "http", "compose"), ("extra-tcp", "tcp", "local-docker")):
        db.execute("INSERT INTO hosts (id,name,management_address,approved,service_type,created_at,provisioning) VALUES (?,?,?,1,?,?,?)",
                   (host, host, "agent", service, AT, provisioning))
    for agent, host in (("low", "lab-low"), ("medium", "lab-medium"), ("hf-extra-tcp", "extra-tcp")):
        db.execute("INSERT INTO agents VALUES (?,?,'hash',1,'1.0',?)", (agent, host, AT))
    pots = (("hp-low", "Demo low", "p-tcp", "lab-low", "stopped", 25), ("hp-medium", "Demo medium", "p-web", "lab-medium", "running", 12),
            ("hp-extra", "Extra TCP", "p-tcp", "extra-tcp", "running", 4))
    for identifier, name, profile, host, desired, generation in pots:
        db.execute("INSERT INTO honeypots (id,name,profile_id,host_id,desired_state,generation,applied_generation,status,last_seen,"
                   "queue_size,created_at,applied_profile_version,ip_address) VALUES (?,?,?,?,?,?,?,?,?,0,?,3,'172.18.0.5')",
                   (identifier, name, profile, host, desired, generation, generation, desired, AT, AT))
    events = (("hp-low", "low", "TCP", 8022), ("hp-low", "low", "TCP", 8022), ("hp-medium", "medium", "HTTP", 8080), ("hp-extra", "hf-extra-tcp", "TCP", 8022))
    for number, (pot, agent, protocol, port) in enumerate(events):
        db.execute("INSERT INTO telemetry_events (event_uid,honeypot_id,agent_id,session_id,timestamp,received_at,source_ip,source_port,"
                   "destination_port,protocol,event_type,severity,payload) VALUES (?,?,?,?,?,?,'172.18.0.4',40000,?,?,'connection','info','{}')",
                   (f"uid-{number}", pot, agent, f"session-{number}", AT, AT, port, protocol))
    db.execute("INSERT INTO deployments VALUES ('d1','hp-medium','lab-medium','p-web','u1',12,'running',NULL,?,?)", (AT, AT))
    db.execute("INSERT INTO deployments VALUES ('d2','hp-extra','extra-tcp','p-tcp','u1',4,'pending',NULL,?,NULL)", (AT,))
    db.execute("INSERT INTO management_commands VALUES ('c1','hp-extra','start',4,'pending',NULL,?,NULL)", (AT,))
    db.execute("INSERT INTO alert_rules VALUES ('r1','Правило',1,'hp-medium','connection',1,60,'medium')")
    db.execute("INSERT INTO alerts VALUES ('a1','r1','hp-medium','medium','open',?,NULL,'{}')", (AT,))
    db.execute("INSERT INTO audit_logs (actor,action,resource,result,timestamp,details) VALUES ('u1','honeypot.register','hp-low','success',?,'{}')", (AT,))
    db.commit()
    db.close()


async def test_two_slot_installation_becomes_dynamic_instances_without_data_loss(tmp_path):
    path = tmp_path / "legacy.db"
    url = "sqlite+aiosqlite:///" + path.as_posix()
    alembic(url, TWO_SLOT_REVISION)
    seed_two_slot_installation(path)
    alembic(url, "head")

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    pots = {row["id"]: row for row in db.execute("SELECT * FROM honeypots")}
    assert set(pots) == {"hp-low", "hp-medium", "hp-extra"}
    assert {row["host_id"] for row in pots.values()} == {"lab-docker"}
    assert [row["id"] for row in db.execute("SELECT id FROM hosts")] == ["lab-docker"]
    assert (pots["hp-low"]["status"], pots["hp-low"]["generation"]) == ("stopping", 26)
    assert (pots["hp-medium"]["status"], pots["hp-medium"]["generation"]) == ("deploying", 13)
    assert json.loads(pots["hp-medium"]["configuration"])["identity"] == "Старая панель"
    assert all(row["profile_version"] == 3 and row["last_seen"] is None for row in pots.values())
    endpoints = {row["honeypot_id"]: row for row in db.execute("SELECT * FROM network_endpoints")}
    assert sorted(row["internal_port"] for row in endpoints.values()) == [8022, 8023, 8080]
    assert endpoints["hp-medium"]["internal_port"] == 8080 and endpoints["hp-medium"]["alias"] == "hp-hp-mediu"
    for identifier, row in pots.items():
        assert json.loads(row["configuration"])["port"] == endpoints[identifier]["internal_port"]
    assert db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0] == 4
    joined = db.execute("SELECT h.name, count(*) FROM telemetry_events e JOIN honeypots h ON h.id = e.honeypot_id GROUP BY h.name ORDER BY h.name").fetchall()
    assert [tuple(row) for row in joined] == [("Demo low", 2), ("Demo medium", 1), ("Extra TCP", 1)]
    agents = {row["id"]: row for row in db.execute("SELECT * FROM agents")}
    assert all(row["retired"] and not row["approved"] and row["host_id"] is None for row in agents.values())
    assert {row["id"]: row["honeypot_id"] for row in agents.values()} == {"low": "hp-low", "medium": "hp-medium", "hf-extra-tcp": "hp-extra"}
    assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM audit_logs").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM honeypot_profiles").fetchone()[0] == 2
    assert [tuple(row) for row in db.execute("SELECT id, status, host_id FROM deployments ORDER BY id")] == [
        ("d1", "running", "lab-docker"), ("d2", "cancelled", "lab-docker")]
    assert db.execute("SELECT status FROM management_commands").fetchone()[0] == "superseded"
    db.close()

    os.environ.setdefault("CONTROLLER_TOKEN", "x" * 48)
    engine = create_async_engine(url)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        await bootstrap(session)
        views = await pot_views(session, (await session.scalars(select(Honeypot).order_by(Honeypot.name))).all())
    await engine.dispose()
    assert [(v["name"], v["service_key"], v["endpoint"]["port"], v["event_count"]) for v in views] == [
        ("Demo low", "tcp-banner", 8022, 2), ("Demo medium", "http-admin", 8080, 1), ("Extra TCP", "tcp-banner", 8023, 1)]
    assert all(v["agent"] is None and v["configuration"]["max_connections"] == 64 for v in views)
