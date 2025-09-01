from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timezone
from flask import url_for

db = SQLAlchemy()

# Association table for many-to-many Post <-> Tag
post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # increased
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    bio = db.Column(db.Text)
    profile_pic = db.Column(db.String(150), nullable=True)
    confirmed = db.Column(db.Boolean, default=False)  # <-- email confirmation
    confirmed_on = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_profile_pic(self):
        return url_for('static', filename='profile_pics/' + self.profile_pic) if self.profile_pic else url_for('static', filename='profile_pics/Default_pfp.jpg')


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)  # increased
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    edited = db.Column(db.Boolean, default=False)
    solved = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('posts', lazy=True))
    tags = db.relationship('Tag', secondary=post_tags, backref=db.backref('posts', lazy='dynamic'))
    # DOIs attached to this post
    dois = db.relationship('DOI', backref='post', lazy=True, cascade="all, delete-orphan")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    edited = db.Column(db.Boolean, default=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    post = db.relationship('Post', backref=db.backref('comments', lazy='dynamic'))
    replies = db.relationship(
        'Comment',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )
    # DOIs attached to this comment (top-level or reply)
    dois = db.relationship('DOI', backref='comment', lazy=True, cascade="all, delete-orphan")


class DOI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # DO NOT make this unique, so the same DOI can be attached to multiple posts/comments
    identifier = db.Column(db.String(255), nullable=False, index=True)
    title = db.Column(db.String(500), nullable=True)
    authors = db.Column(db.String(1000), nullable=True)  # comma-separated
    journal = db.Column(db.String(300), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    url = db.Column(db.String(500), nullable=True)

    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
