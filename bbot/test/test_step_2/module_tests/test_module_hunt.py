from .base import ModuleTestBase


class TestHunt(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "hunt", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "submodule_xss": False,
                "submodule_sqli": False,
                "submodule_cmdi": False,
                "submodule_path": False,
            }
        },
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": '<html><a href="/hackme.php?cipher=xor">ping</a></html>'}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and e.data["description"] == "Found potential INSECURE CRYPTOGRAPHY parameter [cipher]"
            for e in events
        )
