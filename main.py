# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

from app import app

if __name__ == '__main__':
    # Intentionally vulnerable: Running on all interfaces (CKV3_SAST_5)
    app.run(host='0.0.0.0', port=5000, debug=True)
