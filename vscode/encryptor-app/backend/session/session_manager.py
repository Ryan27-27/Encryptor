from flask import session
from datetime import timedelta

class SessionManager:
    def __init__(self, app):
        self.app = app
        self.app.secret_key = 'your_secret_key'  # Change this to a secure key
        self.app.permanent_session_lifetime = timedelta(days=7)  # Set session lifetime

    def create_session(self, user_id):
        session.permanent = True
        session['user_id'] = user_id

    def get_user_id(self):
        return session.get('user_id')

    def is_logged_in(self):
        return 'user_id' in session

    def logout(self):
        session.pop('user_id', None)