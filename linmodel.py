import pandas as pd
import numpy as np
from sklearn import preprocessing
from sklearn.linear_model import Ridge
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score


class LinModel:
    def __init__(self):
        pass

    def getResults(self):
        df = pd.read_csv('train.csv')
        y = df.RESULT
        X = df.drop('RESULT', axis=1)

        scaler = preprocessing.StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=0)

        reg = Ridge(alpha=1.0)
        reg.fit(X_train, y_train)

        y_pred = reg.predict(X_test)
        RMSE = np.sqrt(mean_squared_error(y_pred, y_test))
        R = r2_score(y_pred, y_test)

        return reg, y_pred, RMSE, R

    def getCoef(self):
        return self.getResults()[0].coef_


def main():
    cof = LinModel().getCoef()
    print("Feature Coefficients:", cof)


if __name__ == '__main__':
    main()
