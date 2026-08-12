from ip2domain.web.auth import AuthManager, hash_password, verify_password


def test_password_hash_is_salted_and_verifiable():
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first != second
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("wrong password", first)


def test_user_authentication_and_session(tmp_path):
    auth = AuthManager(str(tmp_path / "auth.db"))
    user = auth.create_user("Alice", "a-secure-password", role="user")

    assert user["username"] == "alice"
    assert "password_hash" not in user
    assert auth.authenticate("ALICE", "wrong-password") is None

    authenticated = auth.authenticate("alice", "a-secure-password")
    token = auth.create_session(authenticated["id"])
    session_user = auth.get_session_user(token)

    assert session_user["id"] == user["id"]
    assert session_user["role"] == "user"

    auth.delete_session(token)
    assert auth.get_session_user(token) is None


def test_disabling_user_revokes_sessions(tmp_path):
    auth = AuthManager(str(tmp_path / "auth.db"))
    user = auth.create_user("operator", "a-secure-password")
    token = auth.create_session(user["id"])

    disabled = auth.set_active(user["id"], False)

    assert disabled["is_active"] is False
    assert auth.authenticate("operator", "a-secure-password") is None
    assert auth.get_session_user(token) is None


def test_first_user_can_be_bootstrapped_as_admin(tmp_path):
    auth = AuthManager(str(tmp_path / "auth.db"))

    assert auth.ensure_admin("admin", "a-secure-password") is True
    assert auth.ensure_admin("other", "another-secure-password") is False
    assert auth.list_users()[0]["role"] == "admin"


def test_user_validation(tmp_path):
    auth = AuthManager(str(tmp_path / "auth.db"))

    try:
        auth.create_user("bad user", "a-secure-password")
        assert False, "invalid username was accepted"
    except ValueError:
        pass

    try:
        auth.create_user("valid", "short")
        assert False, "short password was accepted"
    except ValueError:
        pass


def test_web_login_and_role_authorization(tmp_path, monkeypatch):
    import asyncio
    import importlib
    import httpx

    web_app = importlib.import_module("ip2domain.web.app")
    test_auth = AuthManager(str(tmp_path / "web-auth.db"))
    test_auth.create_user("admin", "admin-secure-password", role="admin")
    monkeypatch.setattr(web_app, "auth_manager", test_auth)
    monkeypatch.delenv("IP2DOMAIN_API_TOKEN", raising=False)

    async def run_flow():
        transport = httpx.ASGITransport(app=web_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            unauthenticated = await client.get("/", follow_redirects=False)
            assert unauthenticated.status_code == 303
            assert unauthenticated.headers["location"] == "/login"

            logged_in = await client.post("/api/auth/login", json={
                "username": "admin", "password": "admin-secure-password"
            })
            assert logged_in.status_code == 200
            assert logged_in.cookies.get("ip2domain_session")
            me = await client.get("/api/auth/me")
            assert me.json()["user"]["role"] == "admin"

            created = await client.post("/api/users", json={
                "username": "analyst",
                "password": "analyst-secure-password",
                "role": "user",
            })
            assert created.status_code == 201
            assert created.json()["user"]["username"] == "analyst"

            await client.post("/api/auth/logout")
            assert (await client.get("/api/auth/me")).status_code == 401

            user_login = await client.post("/api/auth/login", json={
                "username": "analyst", "password": "analyst-secure-password"
            })
            assert user_login.status_code == 200
            assert (await client.get("/api/users")).status_code == 403

            changed = await client.put("/api/auth/password", json={
                "current_password": "analyst-secure-password",
                "new_password": "analyst-new-secure-password",
            })
            assert changed.status_code == 200
            assert (await client.get("/api/auth/me")).status_code == 200

            await client.post("/api/auth/logout")
            old_login = await client.post("/api/auth/login", json={
                "username": "analyst", "password": "analyst-secure-password"
            })
            assert old_login.status_code == 401
            new_login = await client.post("/api/auth/login", json={
                "username": "analyst", "password": "analyst-new-secure-password"
            })
            assert new_login.status_code == 200

    asyncio.run(run_flow())
