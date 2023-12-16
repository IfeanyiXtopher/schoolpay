from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Admin(db.Model):
    admin_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    admin_firstname = db.Column(db.String(100), index=True)
    admin_lastname = db.Column(db.String(100), index=True)
    admin_email = db.Column(db.String(120))
    admin_password = db.Column(db.String(200), nullable=True)
    admin_staffid = db.Column(db.String(100), index=True)
    user_pix=db.Column(db.String(120),nullable=True)
    is_default_pwd = db.Column(db.Boolean, default=True)


class Students(db.Model):
    std_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    std_firstname = db.Column(db.String(64), index=True)
    std_lastname = db.Column(db.String(64), index=True)
    std_othername = db.Column(db.String(64), nullable=True)
    std_regnumber = db.Column(db.String(64), index=True)
    std_dob = db.Column(db.DateTime(), index=True)
    std_enrrodate = db.Column(db.DateTime())
    std_pswd = db.Column(db.String(200), nullable=False)
    is_default_pwd = db.Column(db.Boolean, default=True)
    std_email = db.Column(db.String(80), nullable=True)
    std_pix = db.Column(db.String(120),nullable=True)
    std_regdate = db.Column(db.DateTime(), default=datetime.utcnow)
    #Foreign keys
    std_campusid = db.Column(db.Integer(), db.ForeignKey('campus.camp_id'))#Note that the foreignkey is set on tablename Foreignkey('campus.campusid')
    std_studentclassid = db.Column(db.Integer(), db.ForeignKey('studentclass.class_id'))
    std_studentlevelid = db.Column(db.Integer(), db.ForeignKey('studentlevel.level_id'))
    #set relationship
    stdcamp = db.relationship("Campus",back_populates='campstd') #relationship with Campus
    stdlevel = db.relationship("Studentlevel",back_populates='levelstd') #relationship with Studentlevel
    stdclass = db.relationship("Studentclass",back_populates='classstd') #relationship with studentclass
    stdpaid =  db.relationship("Payments",back_populates='paidstd') #relationship with Payments
    std_deets = db.relationship('Studentparent_link',back_populates='link_std')
    student_fees = db.relationship("StudentFees", back_populates='associated_student')
    

class Campus(db.Model):
    camp_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    camp_name = db.Column(db.Enum('Campus1','Campus2','Campus3'), index=True)
    camp_phone = db.Column(db.String(64), nullable=True)
    #set relationship
    campstd = db.relationship("Students",back_populates='stdcamp') #relationship with Student

class Studentclass(db.Model):
    class_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    class_name = db.Column(db.Enum('Primary1','Primary2','Primary3','Primary4','Primary5','Primary6','JSS1','JSS2','JSS3','SS1','SS2','SS3','All'), index=True)
    #set relationship
    classstd = db.relationship("Students",back_populates='stdclass') #relationship with Student
    classfee = db.relationship("Fees",back_populates='feeclass') #relationship with Fees

class Studentlevel(db.Model):
    level_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    level_name = db.Column(db.Enum('Primary','Secondary','All'), index=True)
    #set relationship
    levelstd = db.relationship("Students",back_populates='stdlevel') #relationship with Student
    levelfee = db.relationship("Fees",back_populates='feelevel') #relationship with Fees

class Academic_term(db.Model):
    acaterm_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    acaterm_name = db.Column(db.Enum('First Term','Second Term','Third Term','All'), nullable=False,  server_default=("First Term"))
    #Set Relationship
    termfee = db.relationship("Fees",back_populates='feeterm') #relationship with Fees

class Academic_session(db.Model):
    acases_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    acases_year = db.Column(db.Enum('2015/2016','2016/2017','2017/2018','2018/2019','2019/2020','2020/2021','2021/2022','2022/2023','2023/2024','2024/2025'), nullable=False)
    #Set Relationship
    sesfee = db.relationship("Fees",back_populates='feeses') #relationship with Fees

class Fees(db.Model):
    fees_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    fees_desc = db.Column(db.Text(), nullable = False)
    fees_amount = db.Column(db.Float, nullable=False)
    fees_duedate = db.Column(db.Date())
    #foreign Keys
    fees_levelid = db.Column(db.Integer(), db.ForeignKey('studentlevel.level_id'))
    fees_classid = db.Column(db.Integer(), db.ForeignKey('studentclass.class_id'))
    fees_acatermid = db.Column(db.Integer(), db.ForeignKey('academic_term.acaterm_id'))
    fees_acasesid = db.Column(db.Integer(), db.ForeignKey('academic_session.acases_id'))
    #Set Relationship
    feelevel = db.relationship("Studentlevel",back_populates='levelfee') #relationship with Studentlevel
    feeclass = db.relationship("Studentclass",back_populates='classfee') #relationship with Studentclass
    feeterm = db.relationship("Academic_term",back_populates='termfee') #relationship with Academic_term
    feeses = db.relationship("Academic_session",back_populates='sesfee') #relationship with Academic_session
    students_fees = db.relationship("StudentFees", back_populates='associated_fee')


class StudentFees(db.Model):
    stdfee_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    stdfee_amount = db.Column(db.Float, nullable=False)  # The amount charged to this student
    stdfee_status = db.Column(db.Enum('Unpaid', 'Partial', 'Paid', 'Waived', 'Pending'), default='Unpaid')
    # Foreign keys
    stdfee_std_id = db.Column(db.Integer(), db.ForeignKey('students.std_id'))
    stdfee_fee_id = db.Column(db.Integer(), db.ForeignKey('fees.fees_id'))   
    # Relationships
    associated_student = db.relationship("Students", back_populates='student_fees')
    associated_fee = db.relationship("Fees", back_populates='students_fees')
    payment = db.relationship("Payments", uselist=False, back_populates="associated_stdfee")


class Payments(db.Model):
    pay_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    pay_date = db.Column(db.Date())
    pay_amount = db.Column(db.Float, nullable=False)
    pay_method = db.Column(db.Enum('Card','Bank Transfer','Cash Deposite'), nullable=False, default=('Cash Deposite'))
    pay_status = db.Column(db.Enum('Confirmed','Awaiting Confirmation','On Hold','Failed'), nullable=False, default=('Awaiting Confirmation'))
    pay_ref = db.Column(db.String(100))
    pay_verify_deet = db.Column(db.String(100), nullable=True)
    pay_prove = db.Column(db.String(100), nullable=True)
    #foreign keys
    paystd_id = db.Column(db.Integer(), db.ForeignKey('students.std_id'))
    payparent_id = db.Column(db.Integer(), db.ForeignKey('parents.parents_id'))
    pay_stdfee_id = db.Column(db.Integer(), db.ForeignKey('student_fees.stdfee_id'))
    #Relationship
    paidstd =  db.relationship("Students",backref='payments_made') #relationship with Students
    paidparent =  db.relationship("Parents",backref='payments_made') #relationship with Parents
    associated_stdfee = db.relationship("StudentFees", back_populates="payment")


class Parents(db.Model):
    parents_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    parents_fullname = db.Column(db.String(100), index=True)
    parents_relationship =  db.Column(db.Enum('Mother','Father','Guardian'), nullable=False, default=("Mother"))
    parents_email = db.Column(db.String(120))
    parents_phone = db.Column(db.String(120), nullable=False)
    parents_pwd = db.Column(db.String(200), nullable=False)
    is_default_pwd = db.Column(db.Boolean, default=True)
    #Relationship
    parentpaid =  db.relationship("Payments",back_populates='paidparent') #relationship with payments
    parents_deets = db.relationship('Studentparent_link',back_populates='link_parents')


class Studentparent_link(db.Model):
    stdparentlink_id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    #foreign Key
    stdparentlink_stdid = db.Column(db.Integer(), db.ForeignKey('students.std_id'))
    stdparentlink_parentsid = db.Column(db.Integer(), db.ForeignKey('parents.parents_id'))
    #set relationship
    link_parents = db.relationship('Parents',back_populates='parents_deets')
    link_std = db.relationship('Students',backref='students_deets')




