from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_migrate import Migrate
from models import db, User, Post, Comment, Tag, DOI
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import os
import re
import requests
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')


# ----------------------------
# Database config with SSL for Render
# ----------------------------
db_url = os.environ.get("DATABASE_URL")
if db_url:
    # Render often gives 'postgres://', SQLAlchemy needs 'postgresql://'
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    # Ensure SSL is required
    if "sslmode=" not in db_url:
        db_url += "?sslmode=require"
else:
    # Fallback for local testing
    db_url = 'sqlite:///C:\\Users\\tomas\\reddit_clone\\instance\\reddit.db'

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

migrate = Migrate(app, db)

# Flask-Mail configuration using environment variables
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', '0') == '1'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', '1') == '1'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define all disciplines
all_disciplines = ['math', 'physics', 'chemistry', 'biology', 'computer science',
                   'economics', 'medicine', 'statistics', 'robotics', 'engineering']


# ----------------------------
# Login loader
# ----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------
# Seed tags once
# ----------------------------
def seed_tags():
    tags = [
        'math',
        'physics',
        'chemistry',
        'biology',
        'computer science',
        'economics',
        'medicine',
        'statistics',
        'robotics',
        'engineering'
    ]

    for tag_name in tags:
        if not Tag.query.filter_by(name=tag_name).first():
            db.session.add(Tag(name=tag_name))
    db.session.commit()

with app.app_context():
    db.create_all()
    seed_tags()

# ----------------------------
# DOI helpers
# ----------------------------
DOI_PATTERN = re.compile(r'^(?:https?://(?:dx\.)?doi\.org/)?(10\.\d{4,9}/\S+)$', re.IGNORECASE)

def normalize_doi(raw: str) -> str | None:
    """Return canonical DOI like '10.xxxx/xxxxx' or None if invalid-ish."""
    if not raw:
        return None
    raw = raw.strip()
    m = DOI_PATTERN.match(raw)
    return m.group(1) if m else None

def fetch_crossref(doi: str) -> dict | None:
    url = f"https://api.crossref.org/works/{doi}"
    try:
        r = requests.get(url, timeout=6)
        if r.status_code != 200:
            return None
        msg = r.json().get("message", {})
        authors = []
        for a in msg.get("author", []) or []:
            given = a.get("given", "")
            family = a.get("family", "")
            full = (given + " " + family).strip()
            if full:
                authors.append(full)
        data = {
            "identifier": doi,
            "title": (msg.get("title") or [""])[0],
            "authors": authors,
            "journal": (msg.get("container-title") or [""])[0],
            "year": None,
            "url": msg.get("URL")
        }
        # year
        parts = (msg.get("issued") or {}).get("date-parts") or []
        if parts and parts[0]:
            data["year"] = parts[0][0]
        return data
    except Exception:
        return None

def fetch_datacite(doi: str) -> dict | None:
    url = f"https://api.datacite.org/works/{doi}"
    try:
        r = requests.get(url, timeout=6)
        if r.status_code != 200:
            return None
        attr = r.json().get("data", {}).get("attributes", {})
        creators = []
        for c in attr.get("creators", []) or []:
            name = c.get("name")
            if not name:
                given = c.get("givenName", "")
                family = c.get("familyName", "")
                name = (given + " " + family).strip()
            if name:
                creators.append(name)
        data = {
            "identifier": doi,
            "title": (attr.get("titles") or [{}])[0].get("title", ""),
            "authors": creators,
            "journal": attr.get("container", None) or attr.get("publisher"),
            "year": attr.get("publicationYear"),
            "url": attr.get("url") or attr.get("landingPage")
        }
        return data
    except Exception:
        return None

def fetch_doi_metadata(doi: str) -> dict | None:
    """Crossref first, then DataCite. Returns dict or None."""
    doi_norm = normalize_doi(doi)
    if not doi_norm:
        return None
    data = fetch_crossref(doi_norm)
    if data:
        return data
    return fetch_datacite(doi_norm)

@app.route("/test-email")
def test_email():
    msg = Message("Test Email", recipients=["rietakahashinew@gmail.com"])
    msg.body = "This is a test email from your Flask app."
    try:
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return f"Failed to send email: {e}"
    
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

# ----------------------------
# Email sending helpers
# ----------------------------

def send_email(to_email, subject, html_body):
    """Generic function to send an email via Flask-Mail"""
    msg = Message(subject, recipients=[to_email], html=html_body)
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")


def send_confirmation_email(user):
    """Send email confirmation link for a user"""
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('email/activate.html', confirm_url=confirm_url, user=user)
    subject = "Please confirm your email"
    send_email(user.email, subject, html)


# ----------------------------
# POST creation
# ----------------------------
@app.route('/submit', methods=['POST'])
@login_required
def submit():
    title = request.form['title']
    content = request.form['content']
    main_tag = request.form['tag']
    additional_tags = request.form.getlist('additional_tags')

    valid_tags = [t.name for t in Tag.query.all()]

    all_tags = set([main_tag] + additional_tags)
    if not all_tags.issubset(set(valid_tags)):
        flash('Invalid tags selected')
        return redirect(request.referrer or url_for('home'))

    if len(all_tags) > 5:
        flash('You can select up to 4 additional tags only')
        return redirect(request.referrer or url_for('home'))

    new_post = Post(title=title, content=content, user_id=current_user.id)

    tags_objs = Tag.query.filter(Tag.name.in_(all_tags)).all()
    new_post.tags.extend(tags_objs)

    # collect DOIs (optional, multiple)
    raw_dois = request.form.getlist('dois[]')
    clean_dois = []
    for raw in raw_dois:
        doi_norm = normalize_doi(raw)
        if doi_norm:
            clean_dois.append(doi_norm)
        elif raw.strip() != "":
            flash(f"Skipped invalid DOI: {raw}")

    db.session.add(new_post)
    db.session.flush()  # get post id

    # attach DOIs with metadata if available
    for doi in clean_dois:
        meta = fetch_doi_metadata(doi) or {"identifier": doi}
        db.session.add(DOI(
            identifier=meta.get("identifier", doi),
            title=meta.get("title"),
            authors=", ".join(meta.get("authors", []) or []),
            journal=meta.get("journal"),
            year=meta.get("year"),
            url=meta.get("url"),
            post_id=new_post.id
        ))

    db.session.commit()
    return redirect(url_for('dashboard', tag=main_tag))

# ----------------------------
# PROFILE
# ----------------------------
@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    # Only the owner can edit
    if request.method == 'POST' and user.id == current_user.id:
        new_username = request.form.get('username', user.username)
        new_email = request.form.get('email', user.email)
        new_bio = request.form.get('bio', user.bio)

        # Update username
        user.username = new_username
        # Handle email change
        if new_email != user.email:
            user.email = new_email
            user.confirmed = False
            user.confirmed_on = None
            # send_confirmation_email is your function that sends the email
            send_confirmation_email(user)
            flash("Email changed. Please check your email to confirm.", "info")

        # Update bio
        user.bio = new_bio

        # Handle profile picture upload
        if 'profile_pic' in request.files:
            pic = request.files['profile_pic']
            if pic.filename:
                filename = secure_filename(pic.filename)
                filepath = os.path.join('static/profile_pics', filename)
                pic.save(filepath)
                user.profile_pic = filename

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile', username=user.username))

    # Gather data for tabs
    posts = sorted(user.posts, key=lambda p: p.created_at, reverse=True) if hasattr(user, 'posts') else []
    comments = sorted(user.comments, key=lambda c: c.created_at, reverse=True) if hasattr(user, 'comments') else []
    # Flatten DOIs from posts and comments
    dois = [d for c in comments for d in getattr(c, 'dois', [])] + \
           [d for p in posts for d in getattr(p, 'dois', [])]

    return render_template('profile.html', user=user, posts=posts, comments=comments, dois=dois)


# ----------------------------
# COMMENT / REPLY
# ----------------------------
@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    content = request.form['content']
    parent_id = request.form.get('parent_id')

    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # gather DOIs
    raw_dois = request.form.getlist('dois[]')
    provided_clean = [d for d in (normalize_doi(x) for x in raw_dois) if d]

    # Rule: comments (no parent) must include at least one DOI.
    if not parent_id and len(provided_clean) == 0:
        flash("At least one valid DOI is required for comments.")
        return redirect(url_for('post_detail', post_id=post_id))

    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        post_id=post_id,
        parent_id=parent_id if parent_id else None
    )
    db.session.add(new_comment)
    db.session.flush()

    # Attach DOIs if any (optional for replies)
    for doi in provided_clean:
        meta = fetch_doi_metadata(doi) or {"identifier": doi}
        db.session.add(DOI(
            identifier=meta.get("identifier", doi),
            title=meta.get("title"),
            authors=", ".join(meta.get("authors", []) or []),
            journal=meta.get("journal"),
            year=meta.get("year"),
            url=meta.get("url"),
            comment_id=new_comment.id
        ))

    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))

# ----------------------------
# Auth
# ----------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username/email exists
        if User.query.filter_by(username=username).first():
            flash("Username already taken", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for('register'))

        # Create user
        user = User(username=username, email=email)
        user.password_hash = generate_password_hash(password)

        # Handle profile picture
        if 'profile_pic' in request.files:
            pic = request.files['profile_pic']
            if pic.filename:
                filename = secure_filename(pic.filename)
                filepath = os.path.join('static/profile_pics', filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                pic.save(filepath)
                user.profile_pic = filename

        db.session.add(user)
        db.session.commit()

        # Send verification email
        send_confirmation_email(user)

        flash("Registration successful! A confirmation email has been sent.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.utcnow()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account! Thanks!', 'success')
    
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    resend_email_user = None  # default, no resend link

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.confirmed:
                # User exists, password correct, but not verified
                resend_email_user = user  # pass to template
                flash('Your account is not verified yet.', 'warning')
            else:
                login_user(user)
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', resend_email_user=resend_email_user)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

# ----------------------------
# Edit post/comment
# ----------------------------
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        main_tag_name = post.tags[0].name if post.tags else ''
        flash("You can only edit your own posts.")
        return redirect(url_for('dashboard', tag=main_tag_name))

    # Determine main tag
    main_tag = post.tags[0] if post.tags else None

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']

        # Get selected additional tags
        selected_tags = request.form.getlist('additional_tags')
        if len(selected_tags) > 4:
            flash('You can select a maximum of 4 additional disciplines.')
            return redirect(url_for('edit_post', post_id=post.id))

        # Update tags: keep main tag + additional
        post.tags = [main_tag] if main_tag else []
        for tag_name in selected_tags:
            if main_tag and tag_name == main_tag.name:
                continue
            tag = Tag.query.filter_by(name=tag_name).first()
            if tag and tag not in post.tags:
                post.tags.append(tag)

        post.edited = True
        db.session.commit()
        flash('Post updated successfully.')
        return redirect(url_for('post_detail', post_id=post.id))

    # Prepare for template: main tag + alphabetically sorted additional
    main_tag_name = main_tag.name if main_tag else ''
    additional_tags = [t.name for t in post.tags if t.name != main_tag_name]
    sorted_additional = sorted(additional_tags)

    return render_template('edit_post.html', post=post,
                           disciplines=all_disciplines,
                           main_tag=main_tag_name,
                           additional_tags=sorted_additional)




@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id:
        flash("You can only edit your own comments.")
        return redirect(url_for('post_detail', post_id=comment.post_id))

    if request.method == 'POST':
        comment.content = request.form['content']
        comment.edited = True
        db.session.commit()
        flash('Comment updated successfully.')
        return redirect(url_for('post_detail', post_id=comment.post_id))

    return render_template('edit_comment.html', comment=comment)

@app.route('/resend-verification/<int:user_id>')
def resend_verification(user_id):
    user = User.query.get_or_404(user_id)
    if user.confirmed:
        flash("Email is already verified.", "info")
        return redirect(url_for('login'))

    send_confirmation_email(user)
    flash("A new verification email has been sent.", "success")
    return redirect(url_for('login'))


# ----------------------------
# Toggle solved
# ----------------------------
@app.route('/toggle_solved/<int:post_id>')
@login_required
def toggle_solved(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("Only the original poster can mark a question as solved.")
        return redirect(url_for('post_detail', post_id=post.id))

    post.solved = not post.solved
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post.id))

# ----------------------------
# Pages
# ----------------------------
@app.route('/')
def home():
    disciplines = [t.name for t in Tag.query.order_by(Tag.name).all()]
    return render_template('home.html', disciplines=disciplines)

@app.route('/dashboard/<tag>')
def dashboard(tag):
    tag_obj = Tag.query.filter_by(name=tag.lower()).first()
    if not tag_obj:
        flash('Tag not found')
        return redirect(url_for('home'))

    posts = tag_obj.posts.order_by(Post.created_at.desc()).all()
    for post in posts:
        post.sorted_comments = post.comments.order_by(Comment.created_at.asc()).all()

    disciplines = [t.name for t in Tag.query.order_by(Tag.name).all()]

    return render_template('dashboard.html', posts=posts, tag=tag, disciplines=disciplines)

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    post.sorted_comments = post.comments.order_by(Comment.created_at.asc()).all()
    return render_template('post_detail.html', post=post, Comment=Comment)

# ----------------------------
# DOI Preview API (AJAX)
# ----------------------------
@app.get('/doi/preview')
def doi_preview():
    """
    Call with: /doi/preview?doi=10.xxxx/xxxxx or full https://doi.org/...
    Returns JSON with ok + data or ok:false + error.
    """
    raw = request.args.get('doi', '')
    doi = normalize_doi(raw)
    if not doi:
        return jsonify({"ok": False, "error": "Invalid DOI format."}), 400

    data = fetch_doi_metadata(doi)
    if not data:
        return jsonify({"ok": False, "error": "DOI not found in Crossref/DataCite."}), 404

    return jsonify({
        "ok": True,
        "data": {
            "identifier": data.get("identifier", doi),
            "title": data.get("title") or "",
            "authors": data.get("authors") or [],
            "journal": data.get("journal") or "",
            "year": data.get("year"),
            "url": data.get("url") or f"https://doi.org/{doi}"
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
