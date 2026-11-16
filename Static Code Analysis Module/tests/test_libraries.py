from apg.libraries import OriginClassifier, match_library, vendor_prefixes


def test_longest_prefix_wins():
    assert match_library("com.google.firebase.analytics.FirebaseAnalytics")[1] == "Firebase Analytics"
    assert match_library("com.google.firebase.firestore.X")[1] == "Firebase"
    assert match_library("okhttp3.OkHttpClient")[1] == "OkHttp"
    assert match_library("okhttp3x.Foo") is None


def test_origin_classification():
    c = OriginClassifier(["org.fdroid.fdroid", "com.facebook.katana"])
    assert c.classify("org.fdroid.fdroid.MainActivity", False)[0] == "app"
    assert c.classify("com.facebook.katana.Main", False)[0] == "app"
    assert c.classify("com.facebook.ads.AdView", False)[:2] == ("library", "Meta Audience Network")
    assert c.classify("android.location.LocationManager", True)[0] == "framework"
    assert c.classify("a.b.c", False)[0] == "unknown"


def test_vendor_prefix_is_app_code():
    # The PayPal app ships its own code under com.paypal.*, which is also the PayPal SDK prefix.
    assert vendor_prefixes("com.paypal.android.p2pmobile") == ["com.paypal"]
    assert vendor_prefixes("org.fdroid.fdroid") == []
    c = OriginClassifier(["com.paypal.android.p2pmobile", *vendor_prefixes("com.paypal.android.p2pmobile")])
    assert c.classify("com.paypal.oslo.MainActivity", False)[0] == "app"
    assert c.classify("com.braintreepayments.api.Card", False)[:2] == ("library", "Braintree")



def test_include_matches_packages_classes_and_inner_classes():
    from apg.builder import include_matcher
    keep = include_matcher(["com.paypal.oslo.feature.qrc", "com.paypal.oslo.core.User"])
    assert keep("Lcom/paypal/oslo/feature/qrc/ui/Screen;")          # under a package
    assert keep("Lcom/paypal/oslo/core/User;")                      # exact class
    assert keep("Lcom/paypal/oslo/core/User$Address;")              # its inner class
    assert not keep("Lcom/paypal/oslo/core/UserProfile;")           # not a prefix match on names
    assert not keep("Lcom/paypal/oslo/feature/qrcode/X;")           # sibling package
