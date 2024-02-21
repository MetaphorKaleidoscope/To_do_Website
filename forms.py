from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SelectField, DateField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditorField
from wtforms import validators


# #WTForm
class CreateTaskForm(FlaskForm):
    name = StringField("Task name", validators=[DataRequired()])
    activities = StringField("Activity or activities or a list (separate each element with a space)")
    priority = SelectField("Priority", validators=[DataRequired()], choices=['low', 'medium', 'high'])
    state = SelectField("state", validators=[DataRequired()], choices=['To do', 'Doing', 'Done'])
    due_date = DateField("Due date", validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
        email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
        password = PasswordField("Password", validators=[DataRequired()])
        name = StringField("Name", validators=[DataRequired()])
        submit = SubmitField(label="SING ME UP!")


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField(label="LET ME IN!")


class NoteForm(FlaskForm):
    note = CKEditorField("Note", validators=[DataRequired()])
    submit = SubmitField(label="SUBMIT NOTE")
