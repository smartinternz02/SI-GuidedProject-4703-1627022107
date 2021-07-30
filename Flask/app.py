import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
#importing the inputScript file used to analyze the URL
import inputScript 
import requests


#load model
app = Flask(__name__)
from tensorflow.keras.models import load_model
model = load_model('Phishing_Website.h5')

@app.route('/')
def index():
    return render_template('index.html')

#Redirects to the page to give the user iput URL.
@app.route('/predict')
def predict():
    return render_template('Final.html')

#Fetches the URL given by the URL and passes to inputScript
@app.route('/y_predict',methods=['POST'])
def y_predict():
    '''
    For rendering results on HTML GUI
    '''
    url = request.form['URL']
    checkprediction = inputScript.main(url)

    API_KEY = "Enter your API Key"
    token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey": API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
    mltoken = token_response.json()["access_token"]

    header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

    payload_scoring = {
        "input_data": [
            {
                "field": [["having_IPhaving_IP_Address", "URLURL_Length",
                "Shortining_Service", "having_At_Symbol", "double_slash_redirecting",
                "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
                "Domain_registeration_length", "Favicon", "port", "HTTPS_token",
                "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
                "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover",
                "RightClick", "popUpWidnow", "Iframe", "age_of_domain", "DNSRecord",
                "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page","Statistical_report"]],
                "values": checkprediction
            }]
    }

    response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/ml/v4/deployments/fa030a19-86b3-4bfa-b552-191ae9ed1211/predictions?version=2021-07-30', json=payload_scoring, headers={'Authorization': 'Bearer ' + mltoken})
    json_response = response_scoring.json()
    output = json_response['predictions'][0]['values'][0][1][0]
    # prediction = model.predict(checkprediction)
    # prediction1=(prediction[0]>0.5).round()
    # print(prediction1)

    if(output==1):
        pred="Your are safe!!  This is a Legitimate Website."
        
    else:
        pred="You are on the wrong site. Be cautious!"
    return render_template('Final.html', prediction_text='{}'.format(pred),url=url)

#Takes the input parameters fetched from the URL by inputScript and returns the predictions
@app.route('/predict_api',methods=['POST'])
def predict_api():
    '''
    For direct API calls trought request
    '''
    data = request.get_json(force=True)
    prediction = model.y_predict([np.array(list(data.values()))])

    output = prediction[0]
    return jsonify(output)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == "__main__":
    app.run(debug=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
