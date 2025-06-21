from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
import os
import uuid
from dotenv import load_dotenv
from tradelocker import TradeLocker
import stripe
import logging
import requests
from config import get_config

# Get config
config = get_config()

# Use config for Stripe keys - SINGLE SOURCE OF TRUTH
stripe.api_key = config.STRIPE_SECRET_KEY
stripe_public_key = config.STRIPE_PUBLIC_KEY
webhook_secret = config.STRIPE_WEBHOOK_SECRET

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure database
db_config = {
    'user': os.getenv('DB_USER', 'admin'),
    'password': os.getenv('DB_PASSWORD', 'tQ55Nlgify2JGSnKwCAi'),
    'host': os.getenv('DB_HOST', 'tradersimpulse-main.c78skiy68i07.us-east-1.rds.amazonaws.com'),
    'database': os.getenv('DB_NAME', 'tradersimpulse')
}


# Helper functions
def get_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None


def get_account_info(account_id):
    try:
        conn = get_connection()
        if not conn:
            return {}

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM trading_accounts WHERE account_id = %s", (account_id,))
        account_info = cursor.fetchone()
        cursor.close()
        conn.close()

        # Ensure numeric values are properly formatted
        if account_info:
            if 'initial_balance' in account_info and account_info['initial_balance'] is not None:
                account_info['initial_balance'] = float(account_info['initial_balance'])
            if 'account_equity' in account_info and account_info['account_equity'] is not None:
                account_info['account_equity'] = float(account_info['account_equity'])

        return account_info
    except Error as e:
        print(f"Database error: {e}")
        if conn:
            conn.close()
        return {}


def get_trading_settings(account_id):
    try:
        conn = get_connection()
        if not conn:
            return {}

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM trading_accounts WHERE account_id = %s", (account_id,))
        settings = cursor.fetchone()
        cursor.close()
        conn.close()

        # If no settings found, return empty defaults
        if not settings:
            return {
                'daily_loss_limit': {'enabled': False, 'value': 0.0, 'type': 'equity-based'},
                'daily_profit_target': {'enabled': False, 'value': 0.0, 'type': 'equity-based'},
                'weekly_profit_target': {'enabled': False, 'value': 0.0, 'type': 'equity-based'},
                'max_overall_profit': {'enabled': False, 'value': 0.0, 'type': 'balance-based'},
                'max_trades': {'enabled': False, 'value': 0, 'type': 'count-based'},
                'trading_window': {'enabled': False, 'start_time': '09:00', 'end_time': '17:00', 'type': 'time-based'},
                'max_position_size': {'enabled': False, 'value': 0.0, 'type': 'count-based'},
                'lockout': {'enabled': False, 'until': None, 'type': 'time-based'}
            }

        # Format settings for template, handling None values properly
        formatted_settings = {
            'daily_loss_limit': {
                'enabled': bool(settings.get('daily_loss_limit_enabled', 0)),
                'value': float(settings.get('daily_loss_limit') or 0),
                'type': 'equity-based'
            },
            'daily_profit_target': {
                'enabled': bool(settings.get('daily_profit_target_enabled', 0)),
                'value': float(settings.get('daily_profit_target') or 0),
                'type': 'equity-based'
            },
            'weekly_profit_target': {
                'enabled': bool(settings.get('weekly_profit_target_enabled', 0)),
                'value': float(settings.get('weekly_profit_target') or 0),
                'type': 'equity-based'
            },
            'max_overall_profit': {
                'enabled': bool(settings.get('max_overall_profit_enabled', 0)),
                'value': float(settings.get('max_overall_profit') or 0),
                'type': 'balance-based'
            },
            'max_trades': {
                'enabled': bool(settings.get('max_num_of_trades_enabled', 0)),
                'value': int(settings.get('max_num_of_trades') or 0),
                'type': 'count-based'
            },
            'trading_window': {
                'enabled': bool(settings.get('trading_window_enabled', 0)),
                'start_time': settings.get('trading_window_start_time', '09:00'),
                'end_time': settings.get('trading_window_end_time', '17:00'),
                'type': 'time-based'
            },
            'max_position_size': {
                'enabled': bool(settings.get('max_position_size_enabled', 0)),
                'value': float(settings.get('max_position_size') or 0),
                'type': 'count-based'
            },
            # Add lockout settings
            'lockout': {
                'enabled': bool(settings.get('lockout_enabled', 0)),
                'until': settings.get('lockout_until'),
                'type': 'time-based'
            }
        }
        return formatted_settings
    except Error as e:
        print(f"Database error: {e}")
        return {}


def update_settings(account_id, form_data):
    # Process all settings from form and update database
    try:
        conn = get_connection()
        if not conn:
            return False

        cursor = conn.cursor()

        # Build the update query based on form data
        updates = []
        params = []

        # Process each setting
        if 'daily_loss_limit_enabled' in form_data:
            updates.append("daily_loss_limit_enabled = %s")
            params.append(1 if form_data.get('daily_loss_limit_enabled') == 'on' else 0)

            updates.append("daily_loss_limit = %s")
            params.append(float(form_data.get('daily_loss_limit', 0)))

        if 'daily_profit_target_enabled' in form_data:
            updates.append("daily_profit_target_enabled = %s")
            params.append(1 if form_data.get('daily_profit_target_enabled') == 'on' else 0)

            updates.append("daily_profit_target = %s")
            params.append(float(form_data.get('daily_profit_target', 0)))

        if 'weekly_profit_target_enabled' in form_data:
            updates.append("weekly_profit_target_enabled = %s")
            params.append(1 if form_data.get('weekly_profit_target_enabled') == 'on' else 0)

            updates.append("weekly_profit_target = %s")
            params.append(float(form_data.get('weekly_profit_target', 0)))

        if 'max_overall_profit_enabled' in form_data:
            updates.append("max_overall_profit_enabled = %s")
            params.append(1 if form_data.get('max_overall_profit_enabled') == 'on' else 0)

            updates.append("max_overall_profit = %s")
            params.append(float(form_data.get('max_overall_profit', 0)))

        if 'max_num_of_trades_enabled' in form_data:
            updates.append("max_num_of_trades_enabled = %s")
            params.append(1 if form_data.get('max_num_of_trades_enabled') == 'on' else 0)

            updates.append("max_num_of_trades = %s")
            params.append(int(form_data.get('max_num_of_trades', 0)))

        if 'trading_window_enabled' in form_data:
            updates.append("trading_window_enabled = %s")
            params.append(1 if form_data.get('trading_window_enabled') == 'on' else 0)

            if form_data.get('trading_window_start_time'):
                updates.append("trading_window_start_time = %s")
                params.append(form_data.get('trading_window_start_time'))

            if form_data.get('trading_window_end_time'):
                updates.append("trading_window_end_time = %s")
                params.append(form_data.get('trading_window_end_time'))

        if 'max_position_size_enabled' in form_data:
            updates.append("max_position_size_enabled = %s")
            params.append(1 if form_data.get('max_position_size_enabled') == 'on' else 0)

            updates.append("max_position_size = %s")
            params.append(float(form_data.get('max_position_size', 0)))

        if not updates:
            return False

        query = f"UPDATE trading_accounts SET {', '.join(updates)} WHERE account_id = %s"
        params.append(account_id)

        cursor.execute(query, params)
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"Database error: {e}")
        if conn:
            try:
                conn.rollback()
            except:
                pass
            conn.close()
        return False


def update_single_setting(account_id, setting_name, enabled, value=None):
    try:
        conn = get_connection()
        if not conn:
            return False

        cursor = conn.cursor()

        # Map setting_name to database fields
        field_mapping = {
            'daily_loss_limit': ('daily_loss_limit_enabled', 'daily_loss_limit'),
            'daily_profit_target': ('daily_profit_target_enabled', 'daily_profit_target'),
            'weekly_profit_target': ('weekly_profit_target_enabled', 'weekly_profit_target'),
            'max_overall_profit': ('max_overall_profit_enabled', 'max_overall_profit'),
            'max_trades': ('max_num_of_trades_enabled', 'max_num_of_trades'),
            'trading_window': ('trading_window_enabled', None),
            'max_position_size': ('max_position_size_enabled', 'max_position_size'),
        }

        if setting_name not in field_mapping:
            return False

        enabled_field, value_field = field_mapping[setting_name]

        updates = [f"{enabled_field} = %s"]
        params = [1 if enabled else 0]

        if value_field and value:
            updates.append(f"{value_field} = %s")
            params.append(float(value) if setting_name != 'max_trades' else int(value))

        # Special handling for trading window
        if setting_name == 'trading_window':
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time')

            if start_time:
                updates.append("trading_window_start_time = %s")
                params.append(start_time)

            if end_time:
                updates.append("trading_window_end_time = %s")
                params.append(end_time)

        query = f"UPDATE trading_accounts SET {', '.join(updates)} WHERE account_id = %s"
        params.append(account_id)

        cursor.execute(query, params)
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"Database error: {e}")
        if conn:
            try:
                conn.rollback()
            except:
                pass
            conn.close()
        return False


def get_tradelocker_account_state(account_id, token=None):
    """Get real-time account state from TradeLocker API"""
    try:
        # If no token provided, try to get from session
        if not token and 'tradelocker_token' in session:
            token = session.get('tradelocker_token')

        if not token:
            logger.error("No TradeLocker token available")
            return None

        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {token}'
            # Note: The accNum header might be needed for some accounts
            # 'accNum': '3'
        }

        # Determine the correct base URL based on environment
        env = session.get('tradelocker_env', 'demo')
        base_url = f"https://{env}.tradelocker.com/backend-api"

        url = f"{base_url}/trade/accounts/{account_id}/state"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"TradeLocker API error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error getting TradeLocker account state: {str(e)}")
        return None


def calculate_win_rate(trading_data):
    """Calculate win rate from trading data"""
    try:
        # This implementation depends on the structure of the API response
        closed_trades = trading_data.get('closedTrades', [])
        if not closed_trades:
            return 0

        winning_trades = sum(1 for trade in closed_trades if trade.get('profitLoss', 0) > 0)
        return round((winning_trades / len(closed_trades)) * 100)
    except Exception as e:
        logger.error(f"Error calculating win rate: {str(e)}")
        return 0


# Subscription related functions
def handle_subscription_updated(subscription):
    """Handle subscription update events from Stripe webhook"""
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        cancel_at_period_end = subscription.get('cancel_at_period_end', False)
        current_period_end = datetime.fromtimestamp(subscription.get('current_period_end'))

        conn = get_connection()
        cursor = conn.cursor()

        # Update subscription in database
        cursor.execute("""
            UPDATE subscriptions 
            SET status = %s, 
                cancel_at_period_end = %s, 
                current_period_end = %s 
            WHERE stripe_subscription_id = %s
        """, (status, cancel_at_period_end, current_period_end, subscription_id))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Updated subscription {subscription_id} with status {status}")
        return True
    except Exception as e:
        logger.error(f"Error handling subscription update: {str(e)}")
        return False


def handle_subscription_deleted(subscription):
    """Handle subscription deletion events from Stripe webhook"""
    try:
        subscription_id = subscription.get('id')

        conn = get_connection()
        cursor = conn.cursor()

        # Update subscription status to 'canceled' in database
        cursor.execute("""
            UPDATE subscriptions 
            SET status = 'canceled' 
            WHERE stripe_subscription_id = %s
        """, (subscription_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Marked subscription {subscription_id} as canceled")
        return True
    except Exception as e:
        logger.error(f"Error handling subscription deletion: {str(e)}")
        return False


def get_user_subscription(user_id):
    """Get the user's active subscription"""
    try:
        conn = get_connection()
        if not conn:
            return None

        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT s.*, p.name as plan_name, p.max_accounts_allowed 
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            WHERE s.user_id = %s AND s.status = 'active'
            ORDER BY s.created_at DESC LIMIT 1
        """, (user_id,))

        subscription = cursor.fetchone()
        cursor.close()
        conn.close()

        return subscription
    except Exception as e:
        logger.error(f"Error getting user subscription: {str(e)}")
        return None
        
def start_container_for_account(account_id):
    try:
        response = requests.post(
            "http://ec2-54-90-118-183.compute-1.amazonaws.com:5000/start",
            json={"image": "trading-conditions"}
        )

        if response.status_code == 200:
            data = response.json()
            container_id = data.get("container_id")
            uid = data.get("uid")

            # Save to the trading_accounts table
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE trading_accounts 
                    SET container_id = %s, container_uid = %s 
                    WHERE account_id = %s
                """, (container_id, uid, account_id))
                conn.commit()
                cursor.close()
                conn.close()

            return True
        else:
            print("Failed to start container:", response.text)
            return False
    except Exception as e:
        print(f"Error starting container: {str(e)}")
        return False

def check_accounts_limit(user_id):
    """Check if user has reached their account limit based on subscription"""
    try:
        # Get user's active subscription
        subscription = get_user_subscription(user_id)
        if not subscription:
            return False, 0  # No active subscription

        # Count user's current accounts
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT COUNT(*) as count FROM user_accounts 
            WHERE user_id = %s
        """, (user_id,))

        account_count = cursor.fetchone()['count']
        cursor.close()
        conn.close()

        # Check if user has reached their limit
        max_accounts = subscription['max_accounts_allowed']
        return account_count >= max_accounts, max_accounts
    except Exception as e:
        logger.error(f"Error checking account limits: {str(e)}")
        return True, 0  # Default to limiting accounts on error


# Simple User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email=None, accounts=None):
        self.id = id
        self.username = username
        self.email = email
        self.accounts = accounts or []  # List of account IDs
        self.current_account_id = accounts[0] if accounts else None  # Default to first account


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_connection()
        if not conn:
            return None

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            cursor.close()
            conn.close()
            return None

        # Get all accounts for this user
        cursor.execute("""
            SELECT account_id FROM user_accounts 
            WHERE user_id = %s 
            ORDER BY is_default DESC, date_added ASC
        """, (user_id,))
        accounts = [row['account_id'] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        if user_data:
            return User(user_data['id'], user_data['username'], user_data['email'], accounts)
    except Error as e:
        print(f"Database error: {e}")
        if conn:
            conn.close()
    return None


# Define plans globally so they can be used in multiple routes
SUBSCRIPTION_PLANS = [
    {
        'id': 'starter',
        'name': 'Starter',
        'max_accounts_allowed': 1,
        'stripe_monthly_price_id': 'price_1QGVQ1Cir8vKAFowU4SQWAhz',
        'stripe_annual_price_id': 'price_1QGVRECir8vKAFow2clpHCUU',
        'monthly_cost': 29.00,
        'annual_cost': 24.00
    },
    {
        'id': 'premium',
        'name': 'Premium',
        'max_accounts_allowed': 5,
        'stripe_monthly_price_id': 'price_1QGVScCir8vKAFowh4XC3mDa',
        'stripe_annual_price_id': 'price_1QGVTLCir8vKAFow8a6gTBFZ',
        'monthly_cost': 49.00,
        'annual_cost': 39.00
    }
]


@app.before_request
def load_current_account():
    if current_user.is_authenticated:
        # Get account from session or use first available
        account_id = session.get('current_account_id')
        if account_id and account_id in current_user.accounts:
            current_user.current_account_id = account_id
        elif current_user.accounts:
            current_user.current_account_id = current_user.accounts[0]
            session['current_account_id'] = current_user.current_account_id


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('signup'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            conn = get_connection()
            if not conn:
                flash("Database connection error")
                return render_template('login.html')

            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()

            if not user_data or user_data['password'] != password:  # In production, use password hashing
                flash("Invalid username or password")
                cursor.close()
                conn.close()
                return render_template('login.html')

            # Get accounts for this user
            cursor.execute("""
                SELECT account_id FROM user_accounts 
                WHERE user_id = %s 
                ORDER BY is_default DESC, date_added ASC
            """, (user_data['id'],))
            accounts = [row['account_id'] for row in cursor.fetchall()]

            cursor.close()
            conn.close()

            user = User(user_data['id'], user_data['username'], user_data.get('email'), accounts)
            login_user(user)

            # Store current account in session if needed
            if accounts:
                session['current_account_id'] = accounts[0]

            return redirect(url_for('dashboard'))

        except Error as e:
            flash(f"Database error: {e}")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/landing')
def landing():
    """Landing page for non-authenticated users"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        timezone = request.form.get('timezone', 'UTC')

        # Check if email already exists
        try:
            conn = get_connection()
            if not conn:
                flash("Database connection error")
                return render_template('signup.html')

            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Email already registered. Please login or use a different email.")
                cursor.close()
                conn.close()
                return render_template('signup.html')

            # Generate username from email (first part before @)
            username = email.split('@')[0]

            # Check if username exists and append numbers if needed
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                base_username = username
                count = 1
                while True:
                    username = f"{base_username}{count}"
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    if not cursor.fetchone():
                        break
                    count += 1

            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, password, email, fullname, timezone) 
                VALUES (%s, %s, %s, %s, %s)
            """, (username, password, email, fullname, timezone))

            # Get the new user's ID
            user_id = cursor.lastrowid

            # Create a demo trading account for the user
            account_id = f"demo_{username}_{uuid.uuid4().hex[:8]}"
            cursor.execute("""
                INSERT INTO trading_accounts 
                (account_id, env, initial_balance, account_equity) 
                VALUES (%s, %s, %s, %s)
            """, (account_id, 'demo', 10000.00, 10000.00))

            # Link the account to the user
            cursor.execute("""
                INSERT INTO user_accounts 
                (user_id, account_id, is_default, date_added) 
                VALUES (%s, %s, %s, %s)
            """, (user_id, account_id, 1, datetime.now()))

            conn.commit()

            # Log in the new user
            user = User(user_id, username, email, [account_id])
            login_user(user)

            # Redirect to dashboard or onboarding
            flash(f"Welcome to Traders Impulse, {fullname}! Your account has been created.")
            return redirect(url_for('dashboard'))

        except Error as e:
            flash(f"Registration error: {str(e)}")
            logger.error(f"Registration error: {str(e)}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
                cursor.close()
                conn.close()

    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch account information for the current account
    account_info = get_account_info(current_user.current_account_id)

    # Calculate total P/L if not already present
    if account_info and 'initial_balance' in account_info and 'account_equity' in account_info:
        if 'total_pl' not in account_info or account_info['total_pl'] is None:
            if account_info['account_equity'] is None or account_info['initial_balance'] is None:
                account_info['account_equity'] = 0
                account_info['initial_balance'] = 0
            account_info['total_pl'] = account_info['account_equity'] - account_info['initial_balance']

    # Get user's active subscription
    subscription = get_user_subscription(current_user.id)

    # Try to get real-time trading data
    trading_data = None

    # Check if the current account is a TradeLocker account
    if current_user.current_account_id:
        trading_data = get_tradelocker_account_state(current_user.current_account_id)

    # Format trading data for the dashboard
    trading_status = {}
    if trading_data:
        try:
            # Extract key metrics from the TradeLocker response with updated field mappings
            # Use 'N/A' as the default value for missing data
            trading_status = {
                'trades_count': trading_data.get('todayTradesCount', 'N/A'),
                'open_positions': trading_data.get('positionsCount', 'N/A'),
                'daily_pl': trading_data.get('todayNet', 'N/A'),
                'win_rate': calculate_impulses_hit(trading_data)
            }

            # Update account info with projected balance for equity
            if 'projectedBalance' in trading_data:
                account_info['account_equity'] = trading_data.get('projectedBalance')

            # Update total P/L using openNetPnL
            if 'openNetPnL' in trading_data and account_info.get('initial_balance'):
                account_info['total_pl'] = trading_data.get('openNetPnL')

        except Exception as e:
            logger.error(f"Error processing trading data: {str(e)}")
            # Set N/A values for all fields in case of processing error
            trading_status = {
                'trades_count': 'N/A',
                'open_positions': 'N/A',
                'daily_pl': 'N/A',
                'win_rate': 'N/A'
            }
    else:
        # No trading data available, set all fields to N/A
        trading_status = {
            'trades_count': 'N/A',
            'open_positions': 'N/A',
            'daily_pl': 'N/A',
            'win_rate': 'N/A'
        }

    return render_template('dashboard.html',
                           account=account_info,
                           subscription=subscription,
                           trading_status=trading_status)


# New function to calculate impulses hit instead of win rate
def calculate_impulses_hit(trading_data):
    """Calculate how many impulse limits were hit today"""
    try:
        # This is a placeholder - you'll need to implement based on your actual API response structure
        # Count various limits that were hit today
        limits_hit = 0

        # Check if daily loss limit was hit
        if trading_data.get('dailyLossLimitHit', False):
            limits_hit += 1

        # Check if daily profit target was hit
        if trading_data.get('dailyProfitTargetHit', False):
            limits_hit += 1

        # Check if weekly profit target was hit
        if trading_data.get('weeklyProfitTargetHit', False):
            limits_hit += 1

        # Check if max trades limit was hit
        if trading_data.get('maxTradesLimitHit', False):
            limits_hit += 1

        # Check if max position size limit was hit
        if trading_data.get('maxPositionSizeLimitHit', False):
            limits_hit += 1

        # Return the count of limits hit
        return limits_hit
    except Exception as e:
        logger.error(f"Error calculating impulses hit: {str(e)}")
        return 'N/A'  # Return N/A on error

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    # Check if settings are locked
    conn = get_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT lockout_enabled, lockout_until FROM trading_accounts WHERE account_id = %s",
                       (current_user.current_account_id,))
        lockout_info = cursor.fetchone()
        cursor.close()
        conn.close()

        # Check if settings are locked
        is_locked = False
        if lockout_info and lockout_info.get('lockout_enabled') and lockout_info.get('lockout_until'):
            now = datetime.now()
            lockout_until = lockout_info.get('lockout_until')
            if now < lockout_until:
                is_locked = True
                if request.method == 'POST' and request.form.get('lockout_enabled') != 'on':
                    flash("Settings are locked until the lockout period expires")
                    return redirect(url_for('settings'))

    if request.method == 'POST':
        # Gather all settings from the form
        settings_data = {
            'daily_loss_limit_enabled': 1 if request.form.get('daily_loss_limit_enabled') == 'true' else 0,
            'daily_loss_limit': float(request.form.get('daily_loss_limit', 0)),

            'weekly_profit_target_enabled': 1 if request.form.get('weekly_profit_target_enabled') == 'true' else 0,
            'weekly_profit_target': float(request.form.get('weekly_profit_target', 0)),

            'max_num_of_trades_enabled': 1 if request.form.get('max_trades_enabled') == 'true' else 0,
            'max_num_of_trades': int(request.form.get('max_trades', 0)),

            'trading_window_enabled': 1 if request.form.get('trading_window_enabled') == 'true' else 0,
            'trading_window_start_time': request.form.get('trading_window_start'),
            'trading_window_end_time': request.form.get('trading_window_end'),

            'max_position_size_enabled': 1 if request.form.get('max_position_size_enabled') == 'true' else 0,
            'max_position_size': float(request.form.get('max_position_size', 0)),

            'daily_profit_target_enabled': 1 if request.form.get('daily_profit_target_enabled') == 'true' else 0,
            'daily_profit_target': float(request.form.get('daily_profit_target', 0)),

            'max_overall_profit_enabled': 1 if request.form.get('max_overall_profit_enabled') == 'true' else 0,
            'max_overall_profit': float(request.form.get('max_overall_profit', 0))
        }

        # Handle lockout settings
        if request.form.get('lockout_enabled') == 'on':
            settings_data['lockout_enabled'] = 1

            lockout_option = request.form.get('lockout_option')
            if lockout_option == 'eod':
                # End of day - set to 5:00 PM EST (10:00 PM UTC)
                today = datetime.now()
                # If it's already past 5 PM EST, set to tomorrow
                current_hour_est = today.hour - 5  # Simple EST conversion
                if current_hour_est >= 17:  # 5 PM or later
                    today = today + timedelta(days=1)
                settings_data['lockout_until'] = today.replace(hour=17, minute=0, second=0)
            elif lockout_option == 'eow':
                # End of week - set to Friday 5:00 PM EST
                today = datetime.now()
                days_to_friday = (4 - today.weekday()) % 7
                friday = today + timedelta(days=days_to_friday)
                settings_data['lockout_until'] = friday.replace(hour=17, minute=0, second=0)
            elif lockout_option == 'custom':
                # Custom date from calendar at 5:00 PM EST
                custom_date = request.form.get('lockout_custom_date')
                if custom_date:
                    lock_date = datetime.strptime(custom_date, '%Y-%m-%d')
                    settings_data['lockout_until'] = lock_date.replace(hour=17, minute=0, second=0)
        else:
            settings_data['lockout_enabled'] = 0

        # Update all settings in the database
        try:
            conn = get_connection()
            if not conn:
                return jsonify({"success": False, "error": "Database connection error"})

            cursor = conn.cursor()

            # Build SQL update query
            set_clauses = []
            values = []

            for key, value in settings_data.items():
                if value is not None:
                    set_clauses.append(f"{key} = %s")
                    values.append(value)

            if set_clauses:
                query = f"UPDATE trading_accounts SET {', '.join(set_clauses)} WHERE account_id = %s"
                values.append(current_user.current_account_id)

                cursor.execute(query, values)
                conn.commit()

            cursor.close()
            conn.close()

            flash("Settings updated successfully")
            return redirect(url_for('settings'))

        except Exception as e:
            print(f"Error updating settings: {e}")
            flash(f"Error updating settings: {e}")
            return redirect(url_for('settings'))

    # Fetch current settings for the current account
    trading_settings = get_trading_settings(current_user.current_account_id)

    # Add current time to context for lockout check in template
    return render_template('settings.html',
                           settings=trading_settings,
                           now=datetime.now(),
                           is_locked=is_locked if 'is_locked' in locals() else False)


@app.route('/api/update_setting', methods=['POST'])
@login_required
def api_update_setting():
    # Check if settings are locked
    conn = get_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT lockout_enabled, lockout_until FROM trading_accounts WHERE account_id = %s",
                       (current_user.current_account_id,))
        lockout_info = cursor.fetchone()
        cursor.close()
        conn.close()

        # Check if settings are locked
        if lockout_info and lockout_info.get('lockout_enabled') and lockout_info.get('lockout_until'):
            now = datetime.now()
            lockout_until = lockout_info.get('lockout_until')
            if now < lockout_until:
                return jsonify({'success': False, 'error': 'Settings are locked until the lockout period expires'})

    setting_name = request.form.get('setting_name')
    enabled = request.form.get('enabled') == 'true'
    value = request.form.get('value')

    success = update_single_setting(current_user.current_account_id, setting_name, enabled, value)

    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to update setting'})


@app.route('/switch_account/<account_id>')
@login_required
def switch_account(account_id):
    # Verify this account belongs to the user
    if account_id in current_user.accounts:
        current_user.current_account_id = account_id
        # Store the selected account
        session['current_account_id'] = account_id
        flash(f"Switched to account {account_id}")

    return redirect(request.referrer or url_for('dashboard'))


@app.route('/manage_accounts', methods=['GET', 'POST'])
@login_required
def manage_accounts():
    error_message = None
    success_message = None
    tradelocker_accounts = []

    # Get user's subscription first
    subscription = get_user_subscription(current_user.id)

    # Check subscription limits if user has a subscription
    limit_reached = False
    max_accounts = 0
    if subscription:
        limit_reached, max_accounts = check_accounts_limit(current_user.id)

    if request.method == 'POST':
        action = request.form.get('action')

        # Check subscription for actions that require it
        if action in ['add', 'connect_tradelocker', 'add_tradelocker_accounts']:
            # If no subscription, prevent the action
            if not subscription:
                error_message = "You need an active subscription to add accounts. Please subscribe to a plan first."
                return render_template('manage_accounts.html',
                                       error_message=error_message,
                                       success_message=None,
                                       tradelocker_accounts=[],
                                       subscription=None)

            # If they have a subscription, check account limits
            if limit_reached:
                error_message = f"You've reached your account limit ({max_accounts}). Please upgrade your subscription to add more accounts."
                return render_template('manage_accounts.html',
                                       error_message=error_message,
                                       success_message=None,
                                       tradelocker_accounts=tradelocker_accounts,
                                       subscription=subscription)

        # Process specific actions
        if action == 'add':
            new_account_id = request.form.get('account_id')
            # Verify account exists and isn't already linked
            if new_account_id and new_account_id not in current_user.accounts:
                try:
                    conn = get_connection()
                    if conn:
                        cursor = conn.cursor()
                        # Check if the account exists in trading_accounts
                        cursor.execute("SELECT account_id FROM trading_accounts WHERE account_id = %s",
                                       (new_account_id,))
                        if not cursor.fetchone():
                            # Create account in trading_accounts first
                            cursor.execute(
                                "INSERT INTO trading_accounts (account_id, env) VALUES (%s, %s)",
                                (new_account_id, 'demo')
                            )

                        # Now link to user
                        cursor.execute(
                            "INSERT INTO user_accounts (user_id, account_id) VALUES (%s, %s)",
                            (current_user.id, new_account_id)
                        )
                        conn.commit()
                        current_user.accounts.append(new_account_id)
                        success_message = "Account added successfully"
                    cursor.close()
                    conn.close()
                except Error as e:
                    error_message = f"Error adding account: {e}"

        elif action == 'remove':
            account_id = request.form.get('account_id')
            # Don't allow removing the last account
            if account_id and account_id in current_user.accounts and len(current_user.accounts) > 1:
                try:
                    conn = get_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "DELETE FROM user_accounts WHERE user_id = %s AND account_id = %s",
                            (current_user.id, account_id)
                        )
                        conn.commit()
                        current_user.accounts.remove(account_id)

                        # If we removed the current account, switch to another
                        if current_user.current_account_id == account_id:
                            current_user.current_account_id = current_user.accounts[0]
                            session['current_account_id'] = current_user.current_account_id

                        success_message = "Account removed successfully"
                    cursor.close()
                    conn.close()
                except Error as e:
                    error_message = f"Error removing account: {e}"

        elif action == 'set_default':
            account_id = request.form.get('account_id')
            if account_id and account_id in current_user.accounts:
                try:
                    conn = get_connection()
                    if conn:
                        cursor = conn.cursor()
                        # First, reset all defaults
                        cursor.execute(
                            "UPDATE user_accounts SET is_default = 0 WHERE user_id = %s",
                            (current_user.id,)
                        )
                        # Set the new default
                        cursor.execute(
                            "UPDATE user_accounts SET is_default = 1 WHERE user_id = %s AND account_id = %s",
                            (current_user.id, account_id)
                        )
                        conn.commit()
                        success_message = "Default account updated"
                    cursor.close()
                    conn.close()
                except Error as e:
                    error_message = f"Error setting default account: {e}"

        # Handle TradeLocker connection
        elif action == 'connect_tradelocker':
            logger.info("TradeLocker connection attempt started")
            account_type = request.form.get('account_type', 'demo')
            email = request.form.get('email')
            password = request.form.get('password')
            server = request.form.get('server')

            logger.info(f"Attempting to connect to TradeLocker with env={account_type}, email={email}, server={server}")

            try:
                # Connect to TradeLocker API
                tradelocker = TradeLocker(env=account_type)
                logger.debug("TradeLocker instance created")

                jwt_response = tradelocker.get_jwt_token(email, password, server)
                logger.info("JWT token obtained successfully")

                # Store token in session for future use
                session['tradelocker_token'] = jwt_response.get('token')
                session['tradelocker_env'] = account_type

                # Get all accounts
                logger.debug("Fetching accounts from TradeLocker API")
                accounts_response = tradelocker.get_all_accounts()

                # Format accounts for display - adjusted for the actual API response structure
                formatted_accounts = []
                accounts_list = accounts_response.get('accounts', [])

                for account in accounts_list:
                    account_id = account.get('id')
                    account_name = account.get('name', '')
                    account_balance = account.get('accountBalance', '0.00')
                    account_currency = account.get('currency', 'USD')
                    account_num = account.get('accNum', '')

                    # Then pass account_num to the database insertion
                    if account_id:
                        formatted_accounts.append({
                            'id': account_id,
                            'label': f"{account_name} ({account_currency} {account_balance})",
                            'acc_num': account_num,
                            'balance': account_balance
                        })

                logger.info(f"Found {len(formatted_accounts)} accounts")

                # Store the accounts in session for the next step
                session['tradelocker_accounts'] = formatted_accounts
                tradelocker_accounts = formatted_accounts

                if formatted_accounts:
                    success_message = f"Successfully found {len(formatted_accounts)} account(s)"
                else:
                    error_message = "No accounts found for this user"

            except Exception as e:
                logger.error(f"Error connecting to TradeLocker: {str(e)}", exc_info=True)
                error_message = f"Error connecting to TradeLocker: {str(e)}"

        elif action == 'add_tradelocker_accounts':
            selected_accounts = request.form.getlist('selected_accounts')
            account_type = session.get('tradelocker_env', 'demo')

            # Check account limit before adding
            current_count = len(current_user.accounts)
            if subscription and current_count + len(selected_accounts) > subscription['max_accounts_allowed']:
                error_message = f"Adding these accounts would exceed your plan limit of {subscription['max_accounts_allowed']} accounts."
                return render_template('manage_accounts.html',
                                       error_message=error_message,
                                       success_message=None,
                                       tradelocker_accounts=tradelocker_accounts,
                                       subscription=subscription)

            if not selected_accounts:
                error_message = "Please select at least one account to add"
            else:
                try:
                    conn = get_connection()
                    if conn:
                        cursor = conn.cursor()
                        accounts_added = 0

                        # Get the accounts from session
                        tradelocker_accounts = session.get('tradelocker_accounts', [])

                        for account_id in selected_accounts:
                            # Find the account details in the session data
                            account_data = next((acc for acc in tradelocker_accounts if acc['id'] == account_id), None)

                            # Extract account details if available
                            account_balance = 0
                            account_num = ''

                            if account_data:
                                # Parse the label to extract the balance
                                label_parts = account_data.get('label', '').split('(')
                                if len(label_parts) > 1:
                                    balance_part = label_parts[1].replace(')', '').split(' ')
                                    if len(balance_part) > 1:
                                        try:
                                            account_balance = float(balance_part[1])
                                        except:
                                            account_balance = 0

                            # First check if the trading account exists
                            cursor.execute("SELECT account_id FROM trading_accounts WHERE account_id = %s",
                                           (account_id,))
                            if not cursor.fetchone():
                                # Create the account in trading_accounts with ALL default settings
                                cursor.execute("""
                                        INSERT INTO trading_accounts 
                                        (account_id, env, initial_balance, account_equity, 
                                        daily_loss_limit_enabled, daily_loss_limit,
                                        daily_profit_target_enabled, daily_profit_target,
                                        weekly_profit_target_enabled, weekly_profit_target,
                                        max_overall_profit_enabled, max_overall_profit,
                                        max_num_of_trades_enabled, max_num_of_trades,
                                        trading_window_enabled, trading_window_start_time, trading_window_end_time,
                                        max_position_size_enabled, max_position_size,
                                        lockout_enabled, lockout_until) 
                                        VALUES (%s, %s, %s, %s, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '09:00:00', '17:00:00', 0, 0, 0, NULL)
                                    """, (account_id, account_type, account_balance, account_balance))

                            # Now link it to the user if not already linked
                            cursor.execute("""
                                    INSERT IGNORE INTO user_accounts (user_id, account_id) 
                                    VALUES (%s, %s)
                                """, (current_user.id, account_id))

                            if cursor.rowcount > 0:
                                accounts_added += 1
                                if account_id not in current_user.accounts:
                                    current_user.accounts.append(account_id)

                        conn.commit()
                        cursor.close()
                        conn.close()

                        if accounts_added > 0:
                            success_message = f"Successfully added {accounts_added} account(s)"
                            # Clear the accounts from session
                            session.pop('tradelocker_accounts', None)
                        else:
                            error_message = "No new accounts were added"

                except Error as e:
                    error_message = f"Database error: {str(e)}"

    # Get accounts from session if they exist
    if 'tradelocker_accounts' in session:
        tradelocker_accounts = session.get('tradelocker_accounts', [])

    # GET request - show accounts management page
    return render_template('manage_accounts.html',
                           error_message=error_message,
                           success_message=success_message,
                           tradelocker_accounts=tradelocker_accounts,
                           subscription=subscription)


@app.route('/billing')
@login_required
def billing():
    """Redirect to manage_subscription for billing"""
    return redirect(url_for('subscription_manage'))


@app.route('/subscription/manage')
@login_required
def subscription_manage():
    """Show subscription management page"""
    # Get user's current subscription
    subscription = get_user_subscription(current_user.id)

    # Use config for public key instead of hardcoded
    stripe_public_key = config.STRIPE_PUBLIC_KEY

    return render_template('manage_subscription.html',
                           subscription=subscription,
                           plans=SUBSCRIPTION_PLANS,
                           stripe_public_key=stripe_public_key)


@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Create a Stripe checkout session for subscription purchase"""
    try:
        # Stripe API key is already set at the top of the file
        logger.info(f"Creating checkout for user {current_user.id}")
        logger.info(f"Using Stripe key: {stripe.api_key[:7] if stripe.api_key else 'None'}...")
        
        plan_id = request.form.get('plan_id')
        is_annual = request.form.get('is_annual') == 'true'

        # Get plan from global plans variable
        plan = next((p for p in SUBSCRIPTION_PLANS if p['id'] == plan_id), None)
        if not plan:
            logger.error(f"Plan not found: {plan_id}")
            return jsonify({"error": "Plan not found"}), 404

        # Select price ID based on billing frequency
        price_id = plan['stripe_annual_price_id'] if is_annual else plan['stripe_monthly_price_id']

        logger.info(f"Creating checkout session for plan: {plan['name']}, price: {price_id}")

        # Make sure customer email is set
        customer_email = current_user.email or "customer@example.com"

        checkout_session = stripe.checkout.Session.create(
            customer_email=customer_email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.host_url + 'subscription/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'subscription/cancel',
            metadata={
                'plan': plan['name'],
                'max_accounts': plan['max_accounts_allowed']
            }
        )
        
        logger.info(f"Checkout session created: {checkout_session.id}")
        return jsonify({"id": checkout_session.id})
        
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        return jsonify(error=str(e)), 500


@app.route('/subscription/success')
@login_required
def subscription_success():
    """Handle successful Stripe checkout"""
    session_id = request.args.get('session_id')

    try:
        # Retrieve the checkout session
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        subscription = stripe.Subscription.retrieve(checkout_session.subscription)
        customer = stripe.Customer.retrieve(checkout_session.customer)

        # Insert subscription into database
        conn = get_connection()
        cursor = conn.cursor()

        # Find the plan based on price_id - Fixed the data access
        price_id = subscription['items']['data'][0]['price']['id']
        cursor.execute("""
            SELECT id FROM plans 
            WHERE stripe_monthly_price_id = %s OR stripe_annual_price_id = %s
        """, (price_id, price_id))
        plan_result = cursor.fetchone()

        if not plan_result:
            cursor.close()
            conn.close()
            logger.error(f"Plan not found for price_id: {price_id}")
            return "Error: Plan not found", 500

        plan_id = plan_result[0]

        # Add the subscription record
        cursor.execute("""
            INSERT INTO subscriptions 
            (id, user_id, stripe_customer_id, stripe_subscription_id, plan_id, status, current_period_end, cancel_at_period_end)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            str(uuid.uuid4()),
            current_user.id,
            customer.id,
            subscription.id,
            plan_id,
            subscription.status,
            datetime.fromtimestamp(subscription.current_period_end),
            subscription.cancel_at_period_end
        ))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Successfully created subscription for user {current_user.id}")
        
        # Redirect to dashboard with success message
        flash("Subscription successful! Your account has been upgraded.")
        return redirect(url_for('dashboard'))

    except Exception as e:
        logger.error(f"Error processing subscription: {str(e)}")
        logger.error(f"Session ID: {session_id}")
        flash(f"Error processing subscription: {str(e)}")
        return redirect(url_for('dashboard'))


@app.route('/subscription/cancel', methods=['GET', 'POST'])
@login_required
def subscription_cancel():
    """Cancel a subscription at period end"""
    if request.method == 'POST':
        try:
            # Get the user's active subscription
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT stripe_subscription_id FROM subscriptions
                WHERE user_id = %s AND status = 'active'
                LIMIT 1
            """, (current_user.id,))

            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if not result:
                return jsonify({"success": False, "error": "No active subscription found"})

            # Cancel the subscription with Stripe
            stripe_sub_id = result['stripe_subscription_id']
            stripe.Subscription.modify(
                stripe_sub_id,
                cancel_at_period_end=True
            )

            # Update in our database
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE subscriptions
                SET cancel_at_period_end = 1
                WHERE stripe_subscription_id = %s
            """, (stripe_sub_id,))
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({"success": True})
        except Exception as e:
            logger.error(f"Error canceling subscription: {str(e)}")
            return jsonify({"success": False, "error": str(e)})

    # GET request - show cancellation confirmation page
    subscription = get_user_subscription(current_user.id)
    return render_template('cancel_subscription.html', subscription=subscription)


@app.route('/subscription/resume', methods=['POST'])
@login_required
def subscription_resume():
    """Resume a previously canceled subscription"""
    try:
        # Get the user's canceled subscription
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT stripe_subscription_id FROM subscriptions
            WHERE user_id = %s AND status = 'active' AND cancel_at_period_end = 1
            LIMIT 1
        """, (current_user.id,))

        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if not result:
            return jsonify({"success": False, "error": "No canceled subscription found"})

        # Resume the subscription with Stripe
        stripe_sub_id = result['stripe_subscription_id']
        stripe.Subscription.modify(
            stripe_sub_id,
            cancel_at_period_end=False
        )

        # Update in our database
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE subscriptions
            SET cancel_at_period_end = 0
            WHERE stripe_subscription_id = %s
        """, (stripe_sub_id,))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error resuming subscription: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

def stop_container_for_account(account_id):
    """Stop and remove container for a trading account"""
    try:
        conn = get_connection()
        if not conn:
            return False, "Database connection failed"

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT container_id, container_uid FROM trading_accounts WHERE account_id = %s", (account_id,))
        container_info = cursor.fetchone()
        cursor.close()
        conn.close()

        if not container_info or not container_info.get('container_id'):
            return True, "No container found to stop"

        container_id = container_info['container_id']
        
        # Call your container management API to stop the container
        response = requests.post(
            "http://ec2-54-90-118-183.compute-1.amazonaws.com:5000/stop",
            json={"container_id": container_id},
            timeout=30
        )

        if response.status_code == 200:
            logger.info(f"Successfully stopped container {container_id} for account {account_id}")
            
            # Clear container info from database
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE trading_accounts 
                    SET container_id = NULL, container_uid = NULL 
                    WHERE account_id = %s
                """, (account_id,))
                conn.commit()
                cursor.close()
                conn.close()
            
            return True, f"Container {container_id} stopped successfully"
        else:
            logger.error(f"Failed to stop container {container_id}: {response.text}")
            return False, f"Failed to stop container: {response.text}"

    except Exception as e:
        logger.error(f"Error stopping container for account {account_id}: {str(e)}")
        return False, f"Error stopping container: {str(e)}"


# Add this route to your app.py

@app.route('/remove_account', methods=['POST'])
@login_required
def remove_account():
    """Remove a trading account and stop its container"""
    account_id = request.form.get('account_id')
    
    if not account_id:
        return jsonify({"success": False, "error": "Account ID is required"})
    
    # Verify this account belongs to the user
    if account_id not in current_user.accounts:
        return jsonify({"success": False, "error": "Account not found or access denied"})
    
    # Don't allow removing the last account
    if len(current_user.accounts) <= 1:
        return jsonify({"success": False, "error": "Cannot remove your last account"})
    
    try:
        # Stop the container first
        container_stopped, container_message = stop_container_for_account(account_id)
        
        # Remove from user_accounts table
        conn = get_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM user_accounts WHERE user_id = %s AND account_id = %s",
                (current_user.id, account_id)
            )
            conn.commit()
            cursor.close()
            conn.close()
            
            # Update current user's accounts list
            current_user.accounts.remove(account_id)
            
            # If we removed the current account, switch to another
            if current_user.current_account_id == account_id:
                current_user.current_account_id = current_user.accounts[0]
                session['current_account_id'] = current_user.current_account_id
            
            return jsonify({
                "success": True, 
                "message": f"Account removed successfully. {container_message}",
                "redirect": url_for('manage_accounts')
            })
        else:
            return jsonify({"success": False, "error": "Database connection failed"})
            
    except Exception as e:
        logger.error(f"Error removing account {account_id}: {str(e)}")
        return jsonify({"success": False, "error": f"Error removing account: {str(e)}"})
        
@app.route('/user_settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    """Handle user settings (profile, timezone, notifications)"""
    error_message = None
    success_message = None

    # Get current user data
    try:
        conn = get_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT username, email, fullname, timezone, discord_webhook, 
                       notify_trade_closed, notify_limit_reached, notify_daily_summary
                FROM users 
                WHERE id = %s
            """, (current_user.id,))
            user_data = cursor.fetchone()
            cursor.close()
            conn.close()

            # Provide defaults for missing data
            if not user_data:
                user_data = {
                    'username': current_user.username,
                    'email': current_user.email,
                    'fullname': '',
                    'timezone': 'UTC',
                    'discord_webhook': '',
                    'notify_trade_closed': True,
                    'notify_limit_reached': True,
                    'notify_daily_summary': False
                }
    except Error as e:
        logger.error(f"Database error retrieving user data: {str(e)}")
        user_data = {
            'username': current_user.username,
            'email': current_user.email,
            'fullname': '',
            'timezone': 'UTC',
            'discord_webhook': '',
            'notify_trade_closed': True,
            'notify_limit_reached': True,
            'notify_daily_summary': False
        }

    if request.method == 'POST':
        action = request.form.get('action', '')

        # Handle Profile Update
        if action == 'update_profile':
            fullname = request.form.get('fullname', '')
            email = request.form.get('email', '')

            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE users 
                        SET fullname = %s, email = %s 
                        WHERE id = %s
                    """, (fullname, email, current_user.id))
                    conn.commit()
                    cursor.close()
                    conn.close()

                    # Update session data
                    current_user.email = email

                    # Update displayed data
                    user_data['fullname'] = fullname
                    user_data['email'] = email

                    success_message = "Profile information updated successfully"
            except Error as e:
                error_message = f"Error updating profile: {str(e)}"
                logger.error(f"Database error updating profile: {str(e)}")

        # Handle Password Change
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Verify passwords match
            if new_password != confirm_password:
                error_message = "New passwords do not match"
            elif not current_password or not new_password:
                error_message = "All password fields are required"
            else:
                try:
                    conn = get_connection()
                    if conn:
                        cursor = conn.cursor(dictionary=True)
                        cursor.execute("SELECT password FROM users WHERE id = %s", (current_user.id,))
                        user_record = cursor.fetchone()

                        # In production, use password hashing
                        if user_record and user_record['password'] == current_password:
                            # Update password
                            cursor.execute("""
                                UPDATE users 
                                SET password = %s 
                                WHERE id = %s
                            """, (new_password, current_user.id))
                            conn.commit()
                            success_message = "Password changed successfully"
                        else:
                            error_message = "Current password is incorrect"

                        cursor.close()
                        conn.close()
                except Error as e:
                    error_message = f"Error changing password: {str(e)}"
                    logger.error(f"Database error changing password: {str(e)}")

        # Handle Timezone Update
        elif action == 'update_timezone':
            timezone = request.form.get('timezone', 'UTC')

            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor()

                    # Just directly update the timezone without checking if column exists
                    cursor.execute("""
                        UPDATE users 
                        SET timezone = %s 
                        WHERE id = %s
                    """, (timezone, current_user.id))
                    conn.commit()

                    # Add debug logging
                    print(f"Updated timezone to {timezone} for user ID {current_user.id}")

                    cursor.close()
                    conn.close()

                    # Update displayed data
                    user_data['timezone'] = timezone

                    success_message = "Timezone updated successfully"
            except Error as e:
                error_message = f"Error updating timezone: {str(e)}"
                logger.error(f"Database error updating timezone: {str(e)}")

        # For the Discord webhook section:
        elif action == 'update_discord_webhook':
            discord_webhook = request.form.get('discord_webhook', '')
            notify_trade_closed = 1 if request.form.get('notify_trade_closed') else 0
            notify_limit_reached = 1 if request.form.get('notify_limit_reached') else 0
            notify_daily_summary = 1 if request.form.get('notify_daily_summary') else 0

            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor()

                    # Just directly update the webhook settings
                    cursor.execute("""
                        UPDATE users 
                        SET discord_webhook = %s,
                            notify_trade_closed = %s,
                            notify_limit_reached = %s,
                            notify_daily_summary = %s
                        WHERE id = %s
                    """, (discord_webhook, notify_trade_closed, notify_limit_reached,
                          notify_daily_summary, current_user.id))
                    conn.commit()

                    # Add debug logging
                    print(f"Updated webhook to {discord_webhook} for user ID {current_user.id}")

                    cursor.close()
                    conn.close()

                    # Update displayed data
                    user_data['discord_webhook'] = discord_webhook
                    user_data['notify_trade_closed'] = notify_trade_closed
                    user_data['notify_limit_reached'] = notify_limit_reached
                    user_data['notify_daily_summary'] = notify_daily_summary

                    success_message = "Notification settings updated successfully"
            except Error as e:
                error_message = f"Error updating notification settings: {str(e)}"
                logger.error(f"Database error updating notification settings: {str(e)}")

        # Handle Account Deletion
        elif action == 'delete_account':
            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor()

                    # Delete user accounts
                    cursor.execute("DELETE FROM user_accounts WHERE user_id = %s", (current_user.id,))

                    # Delete user subscriptions
                    cursor.execute("DELETE FROM subscriptions WHERE user_id = %s", (current_user.id,))

                    # Finally delete the user
                    cursor.execute("DELETE FROM users WHERE id = %s", (current_user.id,))

                    conn.commit()
                    cursor.close()
                    conn.close()

                    # Log out the user
                    logout_user()
                    flash("Your account has been permanently deleted")
                    return redirect(url_for('login'))
            except Error as e:
                error_message = f"Error deleting account: {str(e)}"
                logger.error(f"Database error deleting account: {str(e)}")

    # Add current server time
    server_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return render_template('user_settings.html',
                           user_data=user_data,
                           error_message=error_message,
                           success_message=success_message,
                           server_time=server_time)


@app.route('/test_discord_webhook', methods=['POST'])
@login_required
def test_discord_webhook():
    """Test discord webhook by sending a test message"""
    webhook_url = request.form.get('webhook_url', '')

    if not webhook_url:
        return jsonify({"success": False, "error": "Webhook URL is required"})

    try:
        # Prepare test message
        message = {
            "content": "This is a test notification from Traders Impulse Controls.",
            "embeds": [{
                "title": "Test Notification",
                "description": f"This message confirms that your webhook is working correctly.\nSent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "color": 3447003,  # Blue color
                "footer": {
                    "text": "Traders Impulse Controls"
                }
            }]
        }

        # Send test message
        response = requests.post(webhook_url, json=message)

        if response.status_code in [200, 201, 204]:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": f"Discord returned status code: {response.status_code}"})
    except Exception as e:
        logger.error(f"Error testing Discord webhook: {str(e)}")
        return jsonify({"success": False, "error": str(e)})


@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        logger.error(f"Invalid webhook payload: {str(e)}")
        return jsonify({"status": "error"}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logger.error(f"Invalid webhook signature: {str(e)}")
        return jsonify({"status": "error"}), 400

    # Handle the event
    try:
        event_type = event['type']
        logger.info(f"Processing webhook event: {event_type}")

        if event_type == 'customer.subscription.updated':
            subscription = event['data']['object']
            handle_subscription_updated(subscription)
        elif event_type == 'customer.subscription.deleted':
            subscription = event['data']['object']
            handle_subscription_deleted(subscription)
        elif event_type == 'checkout.session.completed':
            session = event['data']['object']
            # If needed, you can handle additional checkout completion logic here
            logger.info(f"Checkout session completed: {session.id}")

        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


def format_amount(amount):
    """Format an amount in cents to a readable currency string"""
    return f"${amount / 100:.2f}"


def format_card_details(payment_method):
    """Format card details for display"""
    card = payment_method.card
    return {
        'brand': card.brand,
        'last4': card.last4,
        'exp_month': card.exp_month,
        'exp_year': card.exp_year
    }


# Database setup function to create necessary tables
def create_tables():
    """Create necessary database tables if they don't exist"""
    conn = get_connection()
    if not conn:
        logger.error("Failed to connect to database for table creation")
        return

    cursor = conn.cursor()

    try:
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                fullname VARCHAR(100),
                timezone VARCHAR(50) DEFAULT 'UTC',
                discord_webhook VARCHAR(255),
                notify_trade_closed TINYINT(1) DEFAULT 1,
                notify_limit_reached TINYINT(1) DEFAULT 1,
                notify_daily_summary TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create trading_accounts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trading_accounts (
                account_id VARCHAR(100) PRIMARY KEY,
                env VARCHAR(20) DEFAULT 'demo',
                initial_balance DECIMAL(15,2) DEFAULT 10000.00,
                account_equity DECIMAL(15,2) DEFAULT 10000.00,
                daily_loss_limit_enabled TINYINT(1) DEFAULT 0,
                daily_loss_limit DECIMAL(15,2) DEFAULT 0,
                daily_profit_target_enabled TINYINT(1) DEFAULT 0,
                daily_profit_target DECIMAL(15,2) DEFAULT 0,
                weekly_profit_target_enabled TINYINT(1) DEFAULT 0,
                weekly_profit_target DECIMAL(15,2) DEFAULT 0,
                max_overall_profit_enabled TINYINT(1) DEFAULT 0,
                max_overall_profit DECIMAL(15,2) DEFAULT 0,
                max_num_of_trades_enabled TINYINT(1) DEFAULT 0,
                max_num_of_trades INT DEFAULT 0,
                trading_window_enabled TINYINT(1) DEFAULT 0,
                trading_window_start_time TIME DEFAULT '09:00:00',
                trading_window_end_time TIME DEFAULT '17:00:00',
                max_position_size_enabled TINYINT(1) DEFAULT 0,
                max_position_size DECIMAL(15,2) DEFAULT 0,
                lockout_enabled TINYINT(1) DEFAULT 0,
                lockout_until DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create user_accounts table (linking users to their trading accounts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                account_id VARCHAR(100) NOT NULL,
                is_default TINYINT(1) DEFAULT 0,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (account_id) REFERENCES trading_accounts(account_id),
                UNIQUE KEY unique_user_account (user_id, account_id)
            )
        """)

        # Create plans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plans (
                id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                max_accounts_allowed INT NOT NULL,
                stripe_monthly_price_id VARCHAR(100) NOT NULL,
                stripe_annual_price_id VARCHAR(100) NOT NULL,
                monthly_cost DECIMAL(10,2) NOT NULL,
                annual_cost DECIMAL(10,2) NOT NULL
            )
        """)

        # Create subscriptions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id VARCHAR(100) PRIMARY KEY,
                user_id INT NOT NULL,
                stripe_customer_id VARCHAR(100) NOT NULL,
                stripe_subscription_id VARCHAR(100) NOT NULL,
                plan_id VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                current_period_end DATETIME,
                cancel_at_period_end BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            )
        """)

        # Create trades table to track user trades
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trades (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_id VARCHAR(100) NOT NULL,
                symbol VARCHAR(20) NOT NULL,
                direction VARCHAR(10) NOT NULL,
                open_time DATETIME NOT NULL,
                close_time DATETIME,
                open_price DECIMAL(15,5) NOT NULL,
                close_price DECIMAL(15,5),
                size DECIMAL(15,5) NOT NULL,
                profit_loss DECIMAL(15,2),
                status VARCHAR(20) DEFAULT 'open',
                FOREIGN KEY (account_id) REFERENCES trading_accounts(account_id)
            )
        """)

        # Create trading_sessions table to track daily sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trading_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_id VARCHAR(100) NOT NULL,
                session_date DATE NOT NULL,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                initial_balance DECIMAL(15,2) NOT NULL,
                final_balance DECIMAL(15,2),
                trades_count INT DEFAULT 0,
                profit_loss DECIMAL(15,2) DEFAULT 0,
                FOREIGN KEY (account_id) REFERENCES trading_accounts(account_id),
                UNIQUE KEY unique_account_session (account_id, session_date)
            )
        """)

        conn.commit()
        logger.info("Database tables created successfully")

        # After creating tables, initialize the plan data
        initialize_plans()

    except Exception as e:
        logger.error(f"Error creating tables: {str(e)}")
        if conn:
            try:
                conn.rollback()
            except:
                pass
    finally:
        cursor.close()
        conn.close()


# Initialize plan data
def initialize_plans():
    """Initialize subscription plan data"""
    plans = [
        {
            'id': 'starter',
            'name': 'Starter',
            'max_accounts_allowed': 1,
            'stripe_monthly_price_id': 'price_1QGVQ1Cir8vKAFowU4SQWAhz',
            'stripe_annual_price_id': 'price_1QGVRECir8vKAFow2clpHCUU',
            'monthly_cost': 29.00,
            'annual_cost': 24.00
        },
        {
            'id': 'premium',
            'name': 'Premium',
            'max_accounts_allowed': 5,
            'stripe_monthly_price_id': 'price_1QGVScCir8vKAFowh4XC3mDa',
            'stripe_annual_price_id': 'price_1QGVTLCir8vKAFow8a6gTBFZ',
            'monthly_cost': 49.00,
            'annual_cost': 39.00
        }
    ]

    conn = get_connection()
    if not conn:
        logger.error("Failed to connect to database for plan initialization")
        return

    cursor = conn.cursor()

    try:
        for plan in plans:
            cursor.execute("""
                INSERT INTO plans 
                (id, name, max_accounts_allowed, stripe_monthly_price_id, stripe_annual_price_id, monthly_cost, annual_cost)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                name = VALUES(name),
                max_accounts_allowed = VALUES(max_accounts_allowed),
                stripe_monthly_price_id = VALUES(stripe_monthly_price_id),
                stripe_annual_price_id = VALUES(stripe_annual_price_id),
                monthly_cost = VALUES(monthly_cost),
                annual_cost = VALUES(annual_cost)
            """, (
                plan['id'],
                plan['name'],
                plan['max_accounts_allowed'],
                plan['stripe_monthly_price_id'],
                plan['stripe_annual_price_id'],
                plan['monthly_cost'],
                plan['annual_cost']
            ))

        conn.commit()
        logger.info("Plans initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing plans: {str(e)}")
    finally:
        cursor.close()
        conn.close()


# Keep the function definition, just remove the decorator
def setup_database():
    """Setup database tables and initial data"""
    create_tables()
    initialize_plans()


if __name__ == '__main__':
    # Setup database on startup - make it resilient
    try:
        setup_database()
        logger.info("Database setup completed successfully")
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        # Don't crash the app, just log the error
        
    # Get port from environment variable (Heroku provides this)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
