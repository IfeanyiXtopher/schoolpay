from flask import Flask
from flask_wtf.csrf import CSRFProtect

from flask_migrate import Migrate
from flask_mail import Mail, Message

csrf = CSRFProtect() #this protects all our (POST) route from csrf attacks whether we are using FlaskForm or not... 
mail=Mail()

def create_app():
    """keepall import that may cause conflict within this 
        function so that anytime we write "from pkg.. imort.. none of these statments will be executed"""
    from project_package.models import db
    myapp=Flask(__name__)   #instantiate an object of Flask so it can be easily imported imported by other modules inthe package
    myapp.config.from_pyfile('config.py',silent=True)
    db.init_app(myapp)
    migrate = Migrate(myapp,db)
    csrf.init_app(myapp)
    mail.__init__(myapp)
    return myapp


#Instantiate an object of Flask so that it can be easily imported by other modules inthe package
myapp = create_app()

#load the route here
from project_package import myadmin_routes, myusers_routes

#load the models, form
from project_package.myforms import *



