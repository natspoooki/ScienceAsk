from flask import Flask, render_template, request, redirect, url_for, flash
from flask_migrate import Migrate
from models import db, User, Post, Comment, Tag
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',  # Render provides this automatically in production
    'sqlite:///C:\\Users\\tomas\\reddit_clone\\instance\\reddit.db'  # fallback for local testing
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('dashboard', tag=main_tag))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)



@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    content = request.form['content']
    parent_id = request.form.get('parent_id')

    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        post_id=post_id,
        parent_id=parent_id if parent_id else None
    )
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        profile_file = request.files.get('profile_pic')
        filename = None
        if profile_file and profile_file.filename != '':
            filename = secure_filename(profile_file.filename)
            profile_file.save(os.path.join('static/profile_pics', filename))

        new_user = User(username=username, profile_pic=filename)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("You can only edit your own posts.")
        return redirect(url_for('dashboard', tag=post.tags[0].name if post.tags else ''))

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.edited = True
        db.session.commit()
        flash('Post updated successfully.')
        return redirect(url_for('post_detail', post_id=post.id))

    return render_template('edit_post.html', post=post)

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


if __name__ == '__main__':
    app.run(debug=True)
