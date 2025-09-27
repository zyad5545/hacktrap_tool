import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# More comprehensive XSS examples for training
xss_examples = [
    "<script>alert('XSS')</script>",
    "<script>alert('XSS');</script>",
    "javascript:alert('XSS')",
    "javascript:alert('XSS');",
    "onerror=alert('XSS')",
    "onload=alert('XSS')",
    "alert('XSS')",
    "prompt('XSS')",
    "confirm('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<select onfocus=alert('XSS')></select>",
    "<video><source onerror=alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>X</button>",
    "<math><mtext></mtext><maction actiontype=statusline#alert('XSS')>",
    "<!--<img src=\"--><img src=x onerror=alert('XSS')>\">",
    "<?xml version=\"1.0\"?><html><script>alert('XSS');</script>",
    "<? echo('<script>alert('XSS')</script>'); ?>",
    "<![CDATA[<script>alert('XSS');</script>]]>",
    "<div style=\"background:url(javascript:alert('XSS'))\">",
    "<div style=\"width:expression(alert('XSS'))\">",
    "<link rel=stylesheet href=\"javascript:alert('XSS');\">",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS');\">",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<embed src=\"javascript:alert('XSS')\"></embed>",
    "<base href=\"javascript:alert('XSS');//\">",
    "<applet code=\"javascript:alert('XSS');\"></applet>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<a href=\"javascript:alert('XSS')\">Click</a>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">Click</a>",
    "<a href=\"vbscript:alert('XSS')\">Click</a>",
    "<a href=\"livescript:alert('XSS')\">Click</a>",
    "<a href=\"file:///etc/passwd\">Click</a>",
    "<a href=\"javas&#99;ript:alert('XSS')\">Click</a>",
    "<a href=\"javas&#x63;ript:alert('XSS')\">Click</a>"
]

# Normal examples
normal_examples = [
    "hello world",
    "search query",
    "normal text",
    "testing",
    "example.com",
    "login page",
    "user input",
    "form data",
    "website content",
    "regular text",
    "how to create a website",
    "python programming",
    "javascript tutorial",
    "web development",
    "css styles",
    "html tags",
    "database design",
    "api integration",
    "responsive design",
    "user experience",
    "password reset",
    "account login",
    "contact information",
    "about us page",
    "product catalog",
    "shopping cart",
    "checkout process",
    "payment methods",
    "shipping options",
    "return policy"
]

# Create labels
xss_labels = [1] * len(xss_examples)
normal_labels = [0] * len(normal_examples)

# Combine data
all_texts = xss_examples + normal_examples
all_labels = xss_labels + normal_labels

# Create and train model
vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1000)
X = vectorizer.fit_transform(all_texts)

clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
clf.fit(X, all_labels)

# Save the model
model = {
    "xss_vect": vectorizer,
    "xss_clf": clf
}

joblib.dump(model, "/app/xss_model.joblib")
print("Improved XSS model created and saved!")
