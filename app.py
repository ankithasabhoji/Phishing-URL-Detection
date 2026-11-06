from flask import Flask, request, jsonify, render_template
from rule_based_model import rule_based_detector
from gnn_model import gnn_detector
import blockchain_util as bc

app = Flask(__name__)


def fuse_results(rule_result, gnn_result):
    """
    Combine GNN and Rule-based predictions.
    Both model scores represent phishing probability/risk.
    """

    gnn_pred, gnn_score = gnn_result

    gnn_label = "PHISHING" if gnn_pred == 1 else "LEGITIMATE"
    rule_label = rule_result["prediction"]

    rule_phishing_score = float(rule_result["confidence"])
    gnn_phishing_score = gnn_score * 100

    if rule_label == gnn_label:

        final_pred = gnn_label

        if final_pred == "PHISHING":
            final_confidence = (
                rule_phishing_score + gnn_phishing_score
            ) / 2
        else:
            final_confidence = (
                (100 - rule_phishing_score)
                + (100 - gnn_phishing_score)
            ) / 2

        explanation = "Both GNN and Rule-Based models agree."

    else:
        final_pred = "PHISHING"

        final_confidence = (
            rule_phishing_score + gnn_phishing_score
        ) / 2

        explanation = (
            "Models disagree. Conservative approach: "
            "mark PHISHING if either model flags it."
        )

    gnn_confidence = (
        gnn_phishing_score
        if gnn_label == "PHISHING"
        else 100 - gnn_phishing_score
    )

    return {
        "final_prediction": final_pred,
        "final_confidence": round(final_confidence, 2),
        "rule_based": rule_result,
        "gnn": {
            "prediction": gnn_label,
            "score": round(gnn_confidence, 2)
        },
        "explanation": explanation
    }


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"].strip()

        # Step 1: Check Blockchain
        blockchain_record = bc.get_record(url)
        if blockchain_record:
            blockchain_record["source"] = "BLOCKCHAIN"
            return render_template("index.html", result=blockchain_record)

        # Step 2: Run Rule-based model
        rule_result = rule_based_detector.predict(url)

        # Step 3: Run GNN model
        gnn_result = gnn_detector.predict(url)

        # Step 4: Fuse results
        final_result = fuse_results(rule_result, gnn_result)
        final_result["url"] = url
        final_result["source"] = "LIVE_PREDICTION"

        # Step 5: Store into Blockchain
        bc.add_block(final_result)

        return render_template("index.html", result=final_result)

    return render_template("index.html")

@app.route("/api/predict", methods=["POST"])
def api_predict():
    data = request.json
    url = data.get("url", "").strip()

    # Step 1: Check Blockchain
    blockchain_record = bc.get_record(url)
    if blockchain_record:
        blockchain_record["source"] = "BLOCKCHAIN"
        return jsonify(blockchain_record)

    # Step 2: Run Rule-based model
    rule_result = rule_based_detector.predict(url)

    # Step 3: Run GNN model
    gnn_result = gnn_detector.predict(url)

    # Step 4: Fuse results
    final_result = fuse_results(rule_result, gnn_result)
    final_result["url"] = url
    final_result["source"] = "LIVE_PREDICTION"

    # Step 5: Store into Blockchain
    bc.add_block(final_result)

    return jsonify(final_result)

if __name__ == "__main__":
    app.run(debug=True)
