#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        
        x = np.array(obj.getFeaturesList()).reshape(1,30) 
        print("X: ",x)

        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        feature_names = {
            0: "Using IP",
            1: "Long URL(>=54)",
            2: "Short URL",
            3: "Symbol @",
            4: "Redirecting //",
            5: "PreFix,Suffix", 
            6: "Sub-Domains", 
            7: "HTTPS", 
            8: "Domain Reg Length(>=12)", 
            9: "Favicon", 
            10: "Non Std.Port", 
            11: "HTTPS Domain URL", 
            12: "Request URL", 
            13: "Anchor URL", 
            14: "Links in Script tags (%<17)", 
            15: "Server Form Handler",
            16: "Info-Email", 
            17: "Abnormal URL", 
            18: "Website Forwarding", 
            19: "StatusBar Cust", 
            20: "Disable Right Click", 
            21: "Using PopUp Window", 
            22: "Iframe Redirection", 
            23: "Age(>=6)", 
            24: "DNS Recording(>=6)", 
            25: "Website Traffic(<100000)", 
            26: "Page Rank(<100000)", 
            27: "Google Index", 
            28: "Links Pointing to URL(<=2)", 
            29: "Status Report", 
            
        }
        feature_dict = {}
        arrayF = obj.getFeaturesList()
        for i, val in enumerate(arrayF):
            feature_name = feature_names[i]
            feature_dict[feature_name] = val

        # if(y_pred ==1 ):
        arrayF = obj.getFeaturesList()
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('index.html',xx =round(y_pro_non_phishing,2),url=url, feature_dict=feature_dict )
    return render_template("index.html", xx =-1)


if __name__ == "__main__":
    app.run(debug=True)