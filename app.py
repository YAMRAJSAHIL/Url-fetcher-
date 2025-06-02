from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
import time
import threading
import logging
from functools import wraps

app = Flask(__name__)

# Configuration
API_KEYS = {"yamraj"}  # Set of valid API keys
REQUIRE_API_KEY = True  # Set to False to disable API key requirement
RATE_LIMIT = 10  # Requests per minute per IP
REQUEST_TIMEOUT = 15  # Seconds

# Rate limiting storage
request_counts = {}
lock = threading.Lock()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_debug.log'),
        logging.StreamHandler()
    ]
)

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        current_time = time.time()
        
        with lock:
            # Initialize or update request count
            if ip not in request_counts:
                request_counts[ip] = {'count': 1, 'start_time': current_time}
            else:
                # Reset counter if more than 1 minute has passed
                if current_time - request_counts[ip]['start_time'] > 60:
                    request_counts[ip] = {'count': 1, 'start_time': current_time}
                else:
                    request_counts[ip]['count'] += 1
            
            # Check if rate limit exceeded
            if request_counts[ip]['count'] > RATE_LIMIT:
                logging.warning(f"Rate limit exceeded for IP: {ip}")
                return jsonify({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'status': 429
                }), 429
        
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not REQUIRE_API_KEY:
            return f(*args, **kwargs)
            
        api_key = request.args.get('key') or (request.json.get('key') if request.is_json else None)
        
        if not api_key:
            logging.warning("API key missing")
            return jsonify({
                'error': 'API key is required',
                'status': 401
            }), 401
        
        if api_key not in API_KEYS:
            logging.warning(f"Invalid API key attempt: {api_key}")
            return jsonify({
                'error': 'Invalid API key',
                'status': 403
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

def check_for_payment_gateway(headers, content_type, cookies, html):
    gateway_keywords = {
        'wise': ['wise', 'transferwise', 'wise.com', 'api.wise', 'wise-payment'],
        'paytabs': ['paytabs', 'paytabs.com', 'pt-payment', 'api.paytabs'],
        'mygate': ['mygate', 'mygate.co.za', 'mygate-payment', 'api.mygate'],
        'payfort': ['payfort', 'payfort.com', 'payfort-payment', 'api.payfort'],
        'telr': ['telr', 'telr.com', 'telr-payment', 'api.telr'],
        'swish': ['swish', 'swish.nu', 'swish-payment', 'api.swish'],
        'iyzico': ['iyzico', 'iyzico.com', 'iyzico-payment', 'api.iyzico'],
        'pesapal': ['pesapal', 'pesapal.com', 'pesapal-payment', 'api.pesapal'],
        'hyperpay': ['hyperpay', 'hyperpay.com', 'hyperpay-payment', 'api.hyperpay'],
        'masterpass': ['masterpass', 'masterpass.com', 'masterpass-payment'],
        'nmi': ['nmi', 'networkmerchants', 'nmi-payment', 'api.nmi'],
        'myfatoorah': ['myfatoorah', 'myfatoorah.com', 'fatoorah-payment'],
        'tap': ['tap', 'tap.company', 'tap-payments', 'api.tap'],
        'knet': ['knet', 'knet.com.kw', 'knet-payment', 'api.knet'],
        'benefit': ['benefit', 'benefit-payment', 'benefit.bh'],
        'omannet': ['omannet', 'omannet-payment', 'oman-payment'],
        'mollie': ['mollie', 'api.mollie.com', 'mollie.com', 'mollie-payment', 'mollie-checkout', 'mollie-form'],
        'square': ['square', 'squareup.com', 'square-payment', 'square-checkout', 'square-form', 'connect.squareup'],
        'stripe': ['stripe', 'checkout.stripe.com', 'js.stripe.com', 'stripe.com', 'stripe-elements', 'stripe.js'],
        'mercadopago': ['mercadopago', 'mercadolibre', 'mercadopago.com', 'mercadopago-checkout', 'mp-checkout'],
        'midtrans': ['midtrans', 'midtrans.com', 'midtrans-payment', 'midtrans-new', 'snap.midtrans'],
        'cashfree': ['cashfree', 'cashfree.com', 'cashfree-payment', 'api.cashfree.com'],
        'instamojo': ['instamojo', 'instamojo.com', 'instamojo-payment', 'api.instamojo'],
        'phonepe': ['phonepe', 'phonepe.com', 'phonepe-payment', 'api.phonepe'],
        'upi': ['upi', 'upi-payment', 'bhim-upi', 'upi://pay', 'vpa='],
        'gpay': ['gpay', 'google-pay', 'googlepay', 'pay.google.com'],
        'applepay': ['apple-pay', 'applepay', 'apple.com/apple-pay', 'apple-pay-button'],
        'cybersource': ['cybersource', 'cybersource.com', 'cybersource-payment', 'secure.cybersource'],
        '2checkout': ['2checkout', '2checkout.com', '2checkout-payment', 'api.2checkout'],
        'eway': ['eway', 'eway.com', 'eway-payment', 'api.ewaypayments'],
        'paypal': ['paypal', 'paypal.com', 'smart/buttons.js', 'checkout.js', 'paypal-checkout', 'www.paypal.com'],
        'braintree': ['braintree', 'braintreegateway.com', 'braintree-api.com', 'data-braintree-name', 'client.braintree'],
        'worldpay': ['worldpay', 'worldpay.com', 'secure.worldpay.com', 'wp-e-commerce', 'payment.worldpay'],
        'authnet': ['authnet', 'authorize.net', 'authorizenet.com', 'accept-sdk', 'api.authorize.net'],
        'recurly': ['recurly', 'recurly.com', 'recurly.js', 'recurly-integration', 'api.recurly'],
        'shopify': ['shopify', 'myshopify', 'shopify.com', 'checkout.shopify.com', 'shop.app'],
        'adyen': ['adyen', 'adyen.com', 'adyen-payment', 'checkoutshopper-live.adyen'],
        'razorpay': ['razorpay', 'razorpay.com', 'checkout.razorpay.com', 'api.razorpay'],
        'paytm': ['paytm', 'paytm.com', 'secure.paytm.in', 'api.paytm', 'staticpg.paytm'],
        'payu': ['payu', 'payu.in', 'secure.payu.in', 'api.payu', 'checkout.payu'],
        'ccavenue': ['ccavenue', 'ccavenue.com', 'secure.ccavenue.com', 'api.ccavenue'],
        'amazonpay': ['amazonpay', 'payments.amazon.com', 'amazon-pay', 'pay.amazon'],
        'klarna': ['klarna', 'klarna.com', 'klarna-payment', 'api.klarna', 'klarna-checkout'],
        'opayo': ['opayo', 'opayo.com', 'sagepay', 'sage-pay', 'api.opayo'],
        'wechatpay': ['wechatpay', 'wechat-pay', 'wechat-payment', 'pay.weixin', 'wxpay'],
        'alipay': ['alipay', 'alipay.com', 'alipay-payment', 'global.alipay'],
        'coinbase': ['coinbase', 'commerce.coinbase', 'coinbase-commerce', 'api.commerce.coinbase'],
        'crypto': ['crypto', 'bitcoin', 'ethereum', 'usdt', 'cryptocurrency'],
        'fiserv': ['fiserv', 'firstdata', 'first-data', 'api.fiserv'],
        'quickbooks': ['quickbooks', 'intuit', 'quickbooks-payment', 'api.quickbooks'],
        'novalnet': ['novalnet', 'novalnet.de', 'novalnet-payment', 'api.novalnet'],
        'checkout': ['checkout.com', 'checkoutapi', 'checkout-payment', 'api.checkout'],
        'dlocal': ['dlocal', 'dlocal.com', 'dlocal-payment', 'api.dlocal'],
        'bluesnap': ['bluesnap', 'bluesnap.com', 'bluesnap-payment', 'api.bluesnap'],
        'payoneer': ['payoneer', 'payoneer.com', 'payoneer-payment', 'api.payoneer'],
        'payfast': ['payfast', 'payfast.co.za', 'payfast-payment', 'api.payfast'],
        'affirm': ['affirm', 'affirm.com', 'affirm-payment', 'api.affirm'],
        'afterpay': ['afterpay', 'afterpay.com', 'afterpay-payment', 'api.afterpay'],
        'sofort': ['sofort', 'sofort.com', 'sofort-payment', 'api.sofort'],
        'ideal': ['ideal', 'ideal-payment', 'ideal.nl', 'api.ideal'],
        'bancontact': ['bancontact', 'bancontact.com', 'bancontact-payment', 'api.bancontact'],
        'paysafecard': ['paysafecard', 'paysafecard.com', 'paysafe-payment', 'api.paysafecard'],
        'skrill': ['skrill', 'skrill.com', 'skrill-payment', 'api.skrill'],
        'neteller': ['neteller', 'neteller.com', 'neteller-payment', 'api.neteller']
    }

    found_gateways = []

    for keyword, values in gateway_keywords.items():
        if (keyword.lower() in content_type.lower() or
                any(key.lower() in str(headers).lower() or 
                    key.lower() in html.lower() or 
                    key.lower() in str(cookies).lower() for key in values)):
            found_gateways.append(keyword.capitalize())

    return list(set(found_gateways))

def check_for_cloudflare(response_text):
    cloudflare_markers = [
        'checking your browser', 'cf-ray', 'cloudflare',
        '__cfduid', '__cflb', '__cf_bm', 'cf_clearance'
    ]
    return any(marker.lower() in response_text.lower() for marker in cloudflare_markers)

def check_for_captcha(response_text):
    captcha_markers = [
        'recaptcha', 'g-recaptcha', 'data-sitekey',
        'captcha', 'cf_captcha', 'arkoselabs', 'hcaptcha'
    ]
    return any(marker.lower() in response_text.lower() for marker in captcha_markers)

def check_for_graphql(response_text):
    graphql_markers = ['graphql', 'application/graphql', '/graphql', 'graphql-api']
    return any(marker.lower() in response_text.lower() for marker in graphql_markers)

def check_for_platform(response_text):
    platform_markers = {
        'woocommerce': ['woocommerce', 'wc-cart', 'wc-ajax', 'wp-woocommerce'],
        'magento': ['magento', 'mageplaza', 'mage-', 'magento_'],
        'shopify': ['shopify', 'myshopify', 'shopify.shop', 'cdn.shopify.com'],
        'prestashop': ['prestashop', 'addons.prestashop', 'prestashop-core'],
        'opencart': ['opencart', 'route=common/home', 'catalog/view/theme'],
        'bigcommerce': ['bigcommerce', 'stencil', 'bc-', 'bigcommerce.com'],
        'wordpress': ['wordpress', 'wp-content', 'wp-includes', 'wp-json'],
        'drupal': ['drupal', 'sites/all', 'core/assets', 'drupal.js'],
        'joomla': ['joomla', 'index.php?option=com_', 'media/jui/js'],
        'laravel': ['laravel', '/storage/', 'mix-manifest.json'],
        'react': ['react-app', '__react', 'react-dom', 'react.js'],
        'vue': ['vue.js', '__vue__', 'vue-router', 'vuex'],
        'angular': ['angular.js', 'ng-', 'data-ng-', 'angular.module']
    }

    for platform, markers in platform_markers.items():
        if any(marker.lower() in response_text.lower() for marker in markers):
            return platform.capitalize()
    return None

def check_for_shop_system(response_text):
    shop_markers = {
        'shopify': ['shopify', 'cdn.shopify.com'],
        'woocommerce': ['woocommerce', 'wc-ajax'],
        'magento': ['magento', 'mage-'],
        'prestashop': ['prestashop'],
        'bigcommerce': ['bigcommerce', 'stencil'],
        'opencart': ['opencart']
    }
    
    for system, markers in shop_markers.items():
        if any(marker.lower() in response_text.lower() for marker in markers):
            return system.capitalize()
    return None

@app.route('/detect', methods=['GET', 'POST'])
@rate_limit
@require_api_key
def detect_payment_gateways():
    start_time = time.time()
    
    if request.method == 'GET':
        url = request.args.get('url')
    else:
        url = request.json.get('url')
    
    if not url:
        logging.error("URL parameter missing")
        return jsonify({
            'error': 'URL parameter is required',
            'status': 400
        }), 400
    
    try:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        
        logging.info(f"Processing URL: {url}")
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract cookies
        cookies = response.cookies.get_dict()
        
        # Extract headers
        response_headers = dict(response.headers)
        
        # Extract meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs:
                meta_tags[meta.attrs['name']] = meta.attrs.get('content', '')
            elif 'property' in meta.attrs:
                meta_tags[meta.attrs['property']] = meta.attrs.get('content', '')
        
        # Check for various technologies
        payment_gateways = check_for_payment_gateway(
            headers=response_headers,
            content_type=response_headers.get('Content-Type', ''),
            cookies=cookies,
            html=html
        )
        
        result = {
            'url': url,
            'http_status': response.status_code,
            'error': None,
            'meta': {
                'request_time': round(time.time() - start_time, 3),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'api_version': '2.0'
            },
            'security': {
                'cloudflare': check_for_cloudflare(html),
                'captcha': check_for_captcha(html),
                'waf': 'Cloudflare' if check_for_cloudflare(html) else None
            },
            'technologies': {
                'payment_gateways': payment_gateways,
                'graphql': check_for_graphql(html),
                'platform': check_for_platform(html),
                'shop_system': check_for_shop_system(html)
            },
            'headers': {
                'content_type': response_headers.get('Content-Type'),
                'server': response_headers.get('Server'),
                'x_powered_by': response_headers.get('X-Powered-By')
            },
            'redirects': len(response.history),
            'final_url': response.url
        }
        
        logging.info(f"Successfully processed URL: {url}")
        return jsonify(result)
    
    except requests.exceptions.RequestException as e:
        logging.error(f"Error processing URL {url}: {str(e)}")
        return jsonify({
            'url': url,
            'error': str(e),
            'status': 500,
            'meta': {
                'request_time': round(time.time() - start_time, 3),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        }), 500

@app.route('/')
def home():
    return """
    <h1>Advanced Payment Gateway Detection API</h1>
    <p>Use /detect endpoint with a URL parameter to detect payment gateways</p>
    <p>Example: <a href="/detect?url=https://example.com&key=yamraj">/detect?url=https://example.com&key=yamraj</a></p>
    <h3>API Features:</h3>
    <ul>
        <li>Rate Limiting (10 requests/minute)</li>
        <li>Detailed Technology Detection</li>
        <li>Security Checks (Cloudflare, WAF, Captcha)</li>
        <li>Full Request Debugging</li>
    </ul>
    """

def run_debug_server():
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    logging.info("Starting API server in debug mode...")
    run_debug_server()