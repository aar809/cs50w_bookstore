import os
from flask import Flask, session, flash, jsonify, redirect, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import re
import requests
from datetime import date
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash



app = Flask(__name__)

@app.route('/')
def index():
	return "OK! Yes"

if __name__ == "__main__":
	app.run()