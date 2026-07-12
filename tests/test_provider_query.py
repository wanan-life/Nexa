import unittest

from app.providers.query import translate_provider_query


class ProviderQueryTests(unittest.TestCase):
    def test_translate_common_domain_query(self) -> None:
        query = 'domain.suffix="jd.com"'

        self.assertEqual(translate_provider_query(query, "fofa"), 'domain="jd.com"')
        self.assertEqual(translate_provider_query(query, "hunter_qianxin"), 'domain.suffix="jd.com"')
        self.assertEqual(translate_provider_query(query, "shodan"), "domain=jd.com")
        self.assertEqual(translate_provider_query(query, "quake_360"), 'domain="jd.com"')

    def test_translate_combined_technology_query_for_quake(self) -> None:
        query = 'app="Vue.js" && server="nginx"'

        self.assertEqual(
            translate_provider_query(query, "quake_360"),
            'service.http.component="Vue.js" && service.http.server="nginx"',
        )


if __name__ == "__main__":
    unittest.main()
