from flask import Flask

app = Flask(__name__)


@app.route('/chain')
def Chain():
	return 'Works'
	
if __name__=='__main__':
	app.run(host="10.10.10.2",debug=True,port=8000)
