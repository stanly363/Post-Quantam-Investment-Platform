from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Profile, Portfolio, Stock, Holding, InvestmentTransaction, AuditLog, PQServerKey, Transaction

from . import crypto_utils
from .crypto_utils import get_server_keys, generate_new_key
import time, base64, json
import yfinance as yf
from django.utils import timezone
from .forms import RegistrationForm, InvestForm, TransactionForm
from decimal import Decimal
from django.http import JsonResponse
from .models import PortfolioHistory
from django.db.models import Q
from .models import Message
from .forms import UserUpdateForm

@login_required
def profile_update_view(request):
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been successfully updated.")
            return redirect('profile_update')
        else:
            # Iterate over form errors and add detailed messages
            for field, errors in form.errors.items():
                # Get the field label from the form; if field is '__all__', use a generic label.
                field_label = form.fields[field].label if field in form.fields else "Error"
                for error in errors:
                    messages.error(request, f"{field_label}: {error}")
    else:
        form = UserUpdateForm(instance=request.user)
    return render(request, 'profile_update.html', {'form': form})

@login_required
def create_chat_view(request):
    """
    Displays a form where the current user can enter a username to start a chat.
    Upon submission, verifies that the user exists and redirects to the chat detail view.
    """
    if request.method == 'POST':
        username = request.POST.get("username").strip()
        if username == request.user.username:
            messages.error(request, "You cannot chat with yourself.")
            return redirect('create_chat')
        try:
            other_user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "User does not exist.")
            return redirect('create_chat')
        # Optionally, you could create an initial (system) message here.
        return redirect('chat', username=other_user.username)
    return render(request, 'create_chat.html')

@login_required
def chat_redirect_view(request):
    """
    Automatically redirect to the chat_detail view for the first conversation partner.
    If no conversations exist, render an empty chat_detail page so the user can start a new chat.
    """
    msgs = Message.objects.filter(Q(sender=request.user) | Q(recipient=request.user)).order_by('-timestamp')
    partners = set()
    for msg in msgs:
        if msg.sender != request.user:
            partners.add(msg.sender)
        if msg.recipient != request.user:
            partners.add(msg.recipient)
    partners = list(partners)
    if partners:
        first_partner = partners[0]
        return redirect('chat', username=first_partner.username)
    else:
        messages.info(request, "No conversations yet. Start a new chat!")
        # Render an empty chat_detail page with no partner selected.
        context = {
            'other_user': None,
            'chat_messages': [],
            'partners': []
        }
        return render(request, 'chat_detail.html', context)

@login_required
def chat_detail_view(request, username):
    """
    Displays the conversation between the current user and the specified other user.
    Also handles sending new messages.
    """
    other_user = get_object_or_404(User, username=username)
    # Retrieve conversation partners for sidebar
    msgs = Message.objects.filter(Q(sender=request.user) | Q(recipient=request.user)).order_by('-timestamp')
    partners = set()
    for msg in msgs:
        if msg.sender != request.user:
            partners.add(msg.sender)
        if msg.recipient != request.user:
            partners.add(msg.recipient)
    partners = list(partners)
    if request.method == 'POST':
        message_text = request.POST.get('message').strip()
        if message_text:
            encrypted_text = crypto_utils.encrypt_message(message_text)
            Message.objects.create(
                sender=request.user,
                recipient=other_user,
                encrypted_text=encrypted_text
            )
            AuditLog.objects.create(
                event=f"{request.user.username} sent a message to {other_user.username}",
                user=request.user
            )
            return redirect('chat', username=username)
    # Retrieve conversation messages
    conversation = Message.objects.filter(
        (Q(sender=request.user) & Q(recipient=other_user)) |
        (Q(sender=other_user) & Q(recipient=request.user))
    ).order_by('timestamp')
    for msg in conversation:
        try:
            msg.decrypted_text = crypto_utils.decrypt_message(msg.encrypted_text)
        except Exception:
            msg.decrypted_text = "Error decrypting message."
    context = {
        'other_user': other_user,
        'chat_messages': conversation,
        'partners': partners
    }
    return render(request, 'chat_detail.html', context)

@login_required
def portfolio_history_view(request):
    portfolio = get_object_or_404(Portfolio, user=request.user)
    current_value = get_current_portfolio_value(portfolio)
    now = timezone.now()
    # Truncate current time to the minute.
    current_minute = now.replace(second=0, microsecond=0)
    # Update or create a history record for the current minute.
    history_record, created = PortfolioHistory.objects.update_or_create(
        portfolio=portfolio,
        timestamp=current_minute,
        defaults={'total_value': current_value}
    )
    # Get all history entries for today.
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    history_entries = PortfolioHistory.objects.filter(
        portfolio=portfolio,
        timestamp__gte=today_start
    ).order_by('timestamp')
    data = [{
        'timestamp': entry.timestamp.strftime("%H:%M"),
        'total_value': float(entry.total_value)
    } for entry in history_entries]
    # Also return the starting value (first record) for depreciation calculations.
    starting_value = data[0]['total_value'] if data else float(current_value)
    return JsonResponse({
        'history': data,
        'starting_value': starting_value,
        'current_value': float(current_value)
    })

def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.profile.role = form.cleaned_data.get('role')
            user.profile.save()
            
            AuditLog.objects.create(
                event=f"User {user.username} registered with role {user.profile.role}.",
                user=user
            )
            messages.success(request, "Registration successful. Please log in.")
            return redirect('login')
        else:
            for field in form:
                for error in field.errors:
                    if field.name == 'username' and 'already exists' in error.lower():
                        messages.error(request, "The username already exists. Please choose a different one.")
                    else:
                        messages.error(request, f"{field.label}: {error}")
            for error in form.non_field_errors():
                messages.error(request, error)
            return redirect('register')
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get("username").strip()
        password = request.POST.get("password").strip()
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            AuditLog.objects.create(
                event=f"User {username} logged in.",
                user=user
            )
            messages.success(request, f"Welcome {username}!")
            if user.profile.role == 'admin':
                return redirect('admin_dashboard')
            else:
                return redirect('portfolio')
        else:
            messages.error(request, "Invalid credentials!")
            return redirect('login')
    return render(request, 'login.html')


@login_required
def logout_view(request):
    AuditLog.objects.create(
        event=f"User {request.user.username} logged out.",
        user=request.user
    )
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login')

@login_required
def rotate_keys_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    if request.method == 'POST':
        PQServerKey.objects.filter(is_active=True).update(is_active=False)
        new_key = generate_new_key()
        AuditLog.objects.create(
            event="Encryption keys rotated. Old keys archived, new key generated.",
            user=request.user
        )
        messages.success(request, "Encryption keys rotated successfully. Old keys have been archived.")
        return redirect('admin_dashboard')
    return render(request, 'rotate_keys_confirm.html')

@login_required
def message(request):  # Ensure Message model is imported
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient').strip()
        message_text = request.POST.get('message').strip()
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            messages.error(request, "Recipient does not exist.")
            return redirect('message')
        # Encrypt the message text
        encrypted_text = crypto_utils.encrypt_message(message_text)
        Message.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_text=encrypted_text
        )
        messages.success(request, "Message sent.")
        return redirect('message')
    else:
        # Retrieve messages where current user is sender or recipient.
        chat_messages = Message.objects.filter(sender=request.user) | Message.objects.filter(recipient=request.user)
        chat_messages = chat_messages.order_by('timestamp')
        # Decrypt each message for display
        for msg in chat_messages:
            try:
                msg.decrypted_text = crypto_utils.decrypt_message(msg.encrypted_text)
            except Exception as e:
                msg.decrypted_text = "Error decrypting message."
        context = {'chat_messages': chat_messages}
        return render(request, 'chat.html', context)


def get_current_portfolio_value(portfolio):
    # Start with cash balance.
    total = portfolio.cash_balance
    # Add value of each holding using the stock's last_price (if available).
    for holding in portfolio.holdings.all():
        if holding.stock.last_price:
            total += holding.shares * holding.stock.last_price
    return total

@login_required
def portfolio_view(request):
    portfolio, created = Portfolio.objects.get_or_create(user=request.user)
    holdings = portfolio.holdings.all()
    cash = float(portfolio.cash_balance)
    
    total_holdings_value = 0
    holding_data = []
    for holding in holdings:
        if holding.stock.last_price:
            value = float(holding.shares) * float(holding.stock.last_price)
        else:
            value = 0
        total_holdings_value += value
        holding_data.append({
            'holding': holding,
            'value': value,
            'percentage': 0,  # We'll update it after calculating total portfolio value.
        })
    
    total_portfolio_value = cash + total_holdings_value
    cash_percentage = (cash / total_portfolio_value * 100) if total_portfolio_value > 0 else 0
    
    # Update each holding's percentage.
    for item in holding_data:
        item['percentage'] = (item['value'] / total_portfolio_value * 100) if total_portfolio_value > 0 else 0

    # Build chart data for the pie chart.
    chart_data = []
    chart_data.append({
        "label": "Cash",
        "value": cash,
        "percentage": cash_percentage
    })
    for item in holding_data:
        chart_data.append({
            "label": item['holding'].stock.ticker,
            "value": item['value'],
            "percentage": item['percentage']
        })
    
    context = {
        'portfolio': portfolio,
        'holdings': holdings,
        'holding_data': holding_data,
        'chart_data': json.dumps(chart_data),
        'total_portfolio_value': total_portfolio_value,
        'cash_percentage': cash_percentage,
    }
    return render(request, 'portfolio.html', context)

@login_required
def stock_list_view(request):
    # Define a list of 20 common stock tickers
    default_tickers = [
        "AAPL", "MSFT", "GOOGL", "AMZN", "TSLA",
        "BRK-B", "JNJ", "V", "WMT", "JPM",
        "PG", "MA", "NVDA", "HD", "DIS",
        "BAC", "XOM", "VZ", "ADBE", "NFLX"
    ]
    
    # Check if we have at least 20 stocks
    current_count = Stock.objects.count()
    if current_count < 20:
        # For each ticker in our list, ensure it exists in the database
        for ticker in default_tickers:
            try:
                yf_ticker = yf.Ticker(ticker)
                info = yf_ticker.info
                company_name = info.get('shortName') or info.get('longName') or ticker
                history = yf_ticker.history(period="1d")
                if not history.empty:
                    last_price = history['Close'].iloc[-1]
                else:
                    last_price = None

                Stock.objects.update_or_create(
                    ticker=ticker,
                    defaults={
                        'company_name': company_name,
                        'last_price': last_price,
                        'last_updated': timezone.now()
                    }
                )
            except Exception as e:
                # Optionally log the error and continue
                print(f"Error updating {ticker}: {e}")
    
    # Now update prices if older than 60 seconds
    stocks = Stock.objects.all().order_by('ticker')
    stock_data = []
    for stock in stocks:
        update_required = True
        if stock.last_updated:
            delta = timezone.now() - stock.last_updated
            if delta.total_seconds() < 60:
                update_required = False
        if update_required:
            try:
                yf_ticker = yf.Ticker(stock.ticker)
                history = yf_ticker.history(period="1d")
                if not history.empty:
                    last_price = history['Close'].iloc[-1]
                else:
                    last_price = stock.last_price
                stock.last_price = last_price
                stock.last_updated = timezone.now()
                stock.save()
            except Exception as e:
                print(f"Error updating {stock.ticker}: {e}")
                last_price = stock.last_price
        else:
            last_price = stock.last_price

        stock_data.append({
            'ticker': stock.ticker,
            'company_name': stock.company_name,
            'last_price': last_price,
        })
    
    return render(request, 'stock_list.html', {'stocks': stock_data})

@login_required
def invest_view(request, ticker):
    stock = get_object_or_404(Stock, ticker=ticker)
    portfolio = get_object_or_404(Portfolio, user=request.user)
    if request.method == 'POST':
        form = InvestForm(request.POST)
        if form.is_valid():
            shares = form.cleaned_data['shares']
            try:
                stock_data = yf.Ticker(stock.ticker)
                price = stock_data.history(period="1d")['Close'].iloc[-1]
            except Exception as e:
                messages.error(request, "Failed to retrieve stock price.")
                return redirect('stock_list')
            total_cost = shares * Decimal(str(price))
            if portfolio.cash_balance < total_cost:
                messages.error(request, "Insufficient funds.")
                return redirect('invest', ticker=ticker)
            portfolio.cash_balance -= total_cost
            portfolio.save()
            holding, created = Holding.objects.get_or_create(portfolio=portfolio, stock=stock)
            holding.shares += shares
            holding.save()
            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                stock=stock,
                transaction_type='BUY',
                shares=shares,
                price=price
            )
            AuditLog.objects.create(
                event=f"User {request.user.username} bought {shares} shares of {stock.ticker} at £{price:.2f}.",
                user=request.user
            )
            messages.success(request, f"Purchased {shares} shares of {stock.ticker} at £{price:.2f} per share.")
            return redirect('portfolio')
    else:
        form = InvestForm()
    return render(request, 'invest.html', {'stock': stock, 'form': form})

@login_required
def admin_dashboard_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    users = User.objects.all().order_by('username')
    total_users = users.count()
    algorithm, server_pub, server_priv = get_server_keys()
    server_public_key = base64.b64encode(server_pub).decode('utf-8')
    transactions = InvestmentTransaction.objects.all().order_by('-timestamp')
    total_transactions = transactions.count()
    total_money = sum(tx.shares * tx.price for tx in transactions) if total_transactions > 0 else 0
    average_transaction = total_money / total_transactions if total_transactions > 0 else 0
    audit_logs = AuditLog.objects.all().order_by('-timestamp')[:10]
    context = {
        'users': users,
        'total_users': total_users,
        'server_algorithm': algorithm,
        'server_public_key': server_public_key,
        'analytics': {
            'total_transactions': total_transactions,
            'total_money_moved': total_money,
            'average_transaction': average_transaction,
        },
        'recent_transactions': transactions[:5],
        'audit_logs': audit_logs,
    }
    return render(request, 'admin_dashboard.html', context)

@login_required
def admin_user_detail_view(request, user_id):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    
    user_obj = get_object_or_404(User, id=user_id)
    # Get (or create) the portfolio for the user
    portfolio, created = Portfolio.objects.get_or_create(user=user_obj)
    holdings = portfolio.holdings.all()
    cash = float(portfolio.cash_balance)
    
    total_holdings_value = 0
    holding_data = []
    for holding in holdings:
        if holding.stock.last_price:
            value = float(holding.shares) * float(holding.stock.last_price)
        else:
            value = 0
        total_holdings_value += value
        holding_data.append({
            'holding': holding,
            'value': value,
            'percentage': 0,  # to be updated
        })
    
    total_portfolio_value = cash + total_holdings_value
    cash_percentage = (cash / total_portfolio_value * 100) if total_portfolio_value > 0 else 0
    
    for item in holding_data:
        item['percentage'] = (item['value'] / total_portfolio_value * 100) if total_portfolio_value > 0 else 0
    
    # Build chart data for the pie chart.
    chart_data = []
    chart_data.append({
        "label": "Cash",
        "value": cash,
        "percentage": cash_percentage
    })
    for item in holding_data:
        chart_data.append({
            "label": item['holding'].stock.ticker,
            "value": item['value'],
            "percentage": item['percentage']
        })
    
    context = {
        'user_obj': user_obj,
        'portfolio': portfolio,
        'holding_data': holding_data,
        'chart_data': json.dumps(chart_data),
        'total_portfolio_value': total_portfolio_value,
        'cash_percentage': cash_percentage,
    }
    return render(request, 'admin_user_detail.html', context)

@login_required
def admin_user_delete_view(request, user_id):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    user_obj = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        AuditLog.objects.create(
            event=f"User {user_obj.username} deleted by admin {request.user.username}.",
            user=request.user
        )
        user_obj.delete()
        messages.success(request, f"User {user_obj.username} deleted successfully.")
        return redirect('admin_dashboard')
    return render(request, 'admin_user_delete_confirm.html', {'user_obj': user_obj})

@login_required
def admin_create_user_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()
            user.profile.role = form.cleaned_data.get('role')
            user.profile.save()
            AuditLog.objects.create(
                event=f"Admin {request.user.username} created user {user.username}.",
                user=request.user
            )
            messages.success(request, f"User {user.username} created successfully.")
            return redirect('admin_dashboard')
        else:
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
            for error in form.non_field_errors():
                messages.error(request, error)
            return redirect('admin_create_user')
    else:
        form = RegistrationForm()
    return render(request, 'admin_create_user.html', {'form': form})

@login_required
def clear_db_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    from .models import PQServerKey
    InvestmentTransaction.objects.all().delete()
    PQServerKey.objects.all().delete()
    crypto_utils.ensure_server_key()
    AuditLog.objects.create(
        event="Database cleared and re-initialized by admin.",
        user=request.user
    )
    messages.info(request, "Database cleared and re-initialized.")
    return redirect('portfolio')

@login_required
def advisor_view(request):
    if request.user.profile.role != 'advisor':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    clients = Profile.objects.filter(role='client')
    AuditLog.objects.create(
        event=f"Advisor {request.user.username} viewed client list.",
        user=request.user
    )
    return render(request, 'advisor.html', {'clients': clients})
