from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired

from wtforms import StringField, SubmitField, TextAreaField, PasswordField
from wtforms.validators import Email, DataRequired,EqualTo,Length

class RegForm(FlaskForm):
    # fname = StringField("First Name",validators=[DataRequired("First Name cannot be empty")])
    # lname = StringField("Last Name",validators=[Length(min=5,message="last name must be upto 5 character")])
    # #useremail = StringField("Email Address",validators=[Email(message="enetr correct email format"),DataRequired("Please enter password")])
    
    # profile = TextAreaField("Your Profile")
    # btnsubmit = SubmitField("Register")

    student_password = PasswordField("Enter Password",validators=[DataRequired(),Length(min=6)])
    student_confirmpassword = PasswordField("Confirm Password",validators=[EqualTo('student_password',message="password must be the same")])

class DpForm(FlaskForm):
    dp = FileField("Upload a Profile Picture", validators=[FileRequired(), FileAllowed(['jpg','png','jpeg'])])
    btnupload = SubmitField("Upload Picture")


