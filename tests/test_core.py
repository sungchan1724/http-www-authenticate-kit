import unittest

from http_www_authenticate_kit import Challenge, parse_www_authenticate, parse_proxy_authenticate


class TestBasic(unittest.TestCase):
    def test_single_basic_challenge(self):
        cs = parse_www_authenticate('Basic realm="Restricted"')
        self.assertEqual(len(cs), 1)
        c = cs[0]
        self.assertEqual(c.scheme, "basic")
        self.assertEqual(c.realm, "Restricted")
        self.assertEqual(c.params, {"realm": "Restricted"})

    def test_token_realm_value(self):
        # realm can be a token, not just a quoted-string.
        cs = parse_www_authenticate("Basic realm=Restricted")
        self.assertEqual(cs[0].realm, "Restricted")

    def test_scheme_case_insensitive(self):
        cs = parse_www_authenticate('BASIC realm="x"')
        self.assertEqual(cs[0].scheme, "basic")

    def test_param_case_insensitive(self):
        cs = parse_www_authenticate('Basic REALM="x"')
        self.assertEqual(cs[0].realm, "x")
        self.assertIn("realm", cs[0].params)

    def test_multiple_params(self):
        cs = parse_www_authenticate('Digest realm="r", qop="auth", nonce="abc", opaque="o"')
        self.assertEqual(cs[0].scheme, "digest")
        self.assertEqual(cs[0].params["qop"], "auth")
        self.assertEqual(cs[0].params["nonce"], "abc")
        self.assertEqual(cs[0].params["opaque"], "o")
        self.assertEqual(cs[0].realm, "r")

    def test_no_realm(self):
        cs = parse_www_authenticate('Bearer error="invalid_token"')
        self.assertIsNone(cs[0].realm)
        self.assertEqual(cs[0].params["error"], "invalid_token")


class TestMultipleChallenges(unittest.TestCase):
    def test_two_challenges(self):
        cs = parse_www_authenticate('Newauth realm="app", type=1, Basic realm="simple"')
        self.assertEqual(len(cs), 2)
        self.assertEqual(cs[0].scheme, "newauth")
        self.assertEqual(cs[0].params["type"], "1")
        self.assertEqual(cs[1].scheme, "basic")
        self.assertEqual(cs[1].realm, "simple")

    def test_three_challenges(self):
        cs = parse_www_authenticate('Basic realm="a", Digest realm="b", Bearer realm="c"')
        self.assertEqual([c.scheme for c in cs], ["basic", "digest", "bearer"])
        self.assertEqual([c.realm for c in cs], ["a", "b", "c"])

    def test_challenges_separated_by_comma_with_spaces(self):
        cs = parse_www_authenticate('Basic realm="a" ,  Digest realm="b"')
        self.assertEqual(len(cs), 2)
        self.assertEqual(cs[1].scheme, "digest")


class TestQuotedStrings(unittest.TestCase):
    def test_escaped_quote_inside_value(self):
        cs = parse_www_authenticate('Basic realm="a\\"b"')
        self.assertEqual(cs[0].realm, 'a"b')

    def test_escaped_backslash(self):
        cs = parse_www_authenticate('Basic realm="a\\\\b"')
        self.assertEqual(cs[0].realm, 'a\\b')

    def test_value_with_comma_in_quotes(self):
        # The comma inside the quoted string must not be treated as a
        # challenge separator.
        cs = parse_www_authenticate('Basic realm="a, b", Bearer realm="c"')
        self.assertEqual(len(cs), 2)
        self.assertEqual(cs[0].realm, "a, b")
        self.assertEqual(cs[1].scheme, "bearer")


class TestEdgeCases(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(parse_www_authenticate(""), [])

    def test_whitespace_only(self):
        self.assertEqual(parse_www_authenticate("   "), [])

    def test_duplicate_param_keeps_last(self):
        cs = parse_www_authenticate('Basic realm="first", realm="second"')
        self.assertEqual(cs[0].realm, "second")

    def test_proxy_authenticate_alias(self):
        cs = parse_proxy_authenticate('Basic realm="p"')
        self.assertEqual(cs[0].scheme, "basic")
        self.assertEqual(cs[0].realm, "p")

    def test_challenge_type(self):
        c = parse_www_authenticate('Basic realm="x"')[0]
        self.assertIsInstance(c, Challenge)

    def test_params_includes_realm(self):
        # realm is surfaced both as a convenience attribute and inside params.
        c = parse_www_authenticate('Basic realm="x"')[0]
        self.assertEqual(c.params["realm"], "x")
        self.assertEqual(c.realm, c.params["realm"])


if __name__ == "__main__":
    unittest.main()
