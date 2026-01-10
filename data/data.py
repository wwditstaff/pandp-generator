from .wmisdb import WMISDB, DBError
from dotenv import load_dotenv
import os
import uuid
from datetime import datetime

load_dotenv()

class Data:
    def __init__(self):
        self.unpaid = []


    def load_unpaid(self):
        try:
            wmisdb = WMISDB()
            conn = wmisdb.connection
            cursor = conn.cursor()
            sql = "exec sp_p_and_p_upload_generator;"
            #
            # grant execute on sp_p_and_p_upload_generator to api
            #
            cursor.execute(sql)
            rows = cursor.fetchall()
            if len(rows) > 0:
                for row in rows:
                    item = {
                        "account_number": row[0],
                        "access_code": row[1],
                        "customer_name": row[2],
                        "amount_due": float(row[3]),
                        "amount_billed": float(row[4]),
                        "bill_date": row[5],
                        "due_date": row[6],
                        "invoice_text": row[7],
                        "invoice": row[8],
                        "charge_type": row[9],
                        "apn": row[10],
                    }
                    self.unpaid.append(item)
            wmisdb = None
        except DBError as err:
            print(f'DB Error:{err}')
        except Exception as err:
            print(f'Unexpected Error:{err}')

        return

    def save_unpaid_as_excel(self, filename: str):
        """ save the unpaid data to an excel file """
        import pandas as pd

        df = pd.DataFrame(self.unpaid)
        df.index += 1
        # if file exists, remove it, then save
        if os.path.exists(filename):
            os.remove(filename)
        df.to_excel(filename)
        return

    def save_unpaid_as_csv(self, filename: str):
        """ save the unpaid data to a csv file """
        import pandas as pd

        df = pd.DataFrame(self.unpaid)
        df.index += 1
        # if file exists, remove it, then save
        if os.path.exists(filename):
            os.remove(filename)
        df.to_csv(filename, index=False)
        return


