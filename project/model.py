from project.database import db  
from flask_login import UserMixin



# User class
class User(UserMixin,db.Model):  
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    approved = db.Column(db.Boolean(), default=False)
    

    # Relationships
    roles = db.relationship('Role', secondary='user_role', backref=db.backref('users', lazy=True))
    customer_dets = db.relationship('Customer', backref='user', lazy=True, uselist=False)
    service_requests = db.relationship('ServiceRequest', backref='user', lazy=True)




# ServiceProfessional class
class ServiceProfessional(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_type = db.Column(db.String(20), nullable=False, index=True)
    service_duration = db.Column(db.Integer, nullable=False)
    experience_year = db.Column(db.Integer, nullable=False)
    service_description = db.Column(db.String(100), nullable=True)
    service_price = db.Column(db.Float, nullable=False)
    rating = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_serviceprofessional_user'), nullable=False)
    


# Role class
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20),unique=True, nullable=False)


# UserRole association table
class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)


# Customer class
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    open_service_request = db.Column(db.Boolean(), nullable=True)
    close_service_request = db.Column(db.Boolean(), nullable=True)
    posted_reviews = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_customer_user'), nullable=False)
    


# ServiceRequest class
class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_request_user'), nullable=False)
    date_of_request = db.Column(db.Date, nullable=False)
    date_of_accept = db.Column(db.Date, nullable=True)  
    date_of_completion = db.Column(db.Date, nullable=True)  
    service_type = db.Column(db.String(50), nullable=False)
    service_professional_id = db.Column(db.Integer, db.ForeignKey('service_professional.id'), nullable=False)
    service_professional = db.relationship('ServiceProfessional', backref='service_requests')
    