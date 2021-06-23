/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.wultra.android.powerauth.core;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static com.wultra.android.powerauth.core.ErrorCode.ENCRYPTION;
import static com.wultra.android.powerauth.core.ErrorCode.GENERAL_FAILURE;
import static com.wultra.android.powerauth.core.ErrorCode.MISSING_REQUESTED_FACTOR;
import static com.wultra.android.powerauth.core.ErrorCode.MISSING_REQUIRED_FACTOR;
import static com.wultra.android.powerauth.core.ErrorCode.OK;
import static com.wultra.android.powerauth.core.ErrorCode.WRONG_CODE;
import static com.wultra.android.powerauth.core.ErrorCode.WRONG_DATA;
import static com.wultra.android.powerauth.core.ErrorCode.WRONG_PARAM;
import static com.wultra.android.powerauth.core.ErrorCode.WRONG_SETUP;
import static com.wultra.android.powerauth.core.ErrorCode.WRONG_STATE;

/**
 * The {@code ErrorCode} constants defines all possible error codes
 * produced by Session class. You normally need to check only
 * if operation ended with OK or not. All other codes are
 * only hints and should be used only for debugging purposes.
 * <p>
 * For example, if the operation fails at WrongState or WrongParam,
 * then it's usually your fault and you're using Session in wrong way.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({OK, WRONG_SETUP, WRONG_STATE, WRONG_PARAM, WRONG_CODE, WRONG_DATA, ENCRYPTION,
        MISSING_REQUESTED_FACTOR, MISSING_REQUIRED_FACTOR, GENERAL_FAILURE})
public @interface ErrorCode
{
    /**
     * Everything is OK.
     */
    int OK = 0;
    /**
     * You have called Session method while session has invalid setup.
     */
    int WRONG_SETUP = 1;
    /**
     * You have called method in wrong Session's state. Usually that
     * means that you're using Session in a wrong way. This kind
     * of error should not be propagated to the UI. It's your
     * responsibility to handle Session states correctly.
     */
    int WRONG_STATE = 2;
    /**
     * You have called method with wrong or missing parameters.
     * Usually this error code means that you're using Session
     * in wrong way and you did not provide all required data.
     * This kind of error should not be propagated to UI. It's
     * your responsibility to handle all user's inputs
     * and validate all responses from server before you
     * ask Session for processing.
     */
    int WRONG_PARAM = 3;
    /**
     * You have provided a wrong activation or recovery code.
     * You should use ActivationCodeUtil class to validate user
     * inputs, before you call other PowerAuth functions.
     */
    int WRONG_CODE = 4;
    /**
     * The provided digital signature is not valid. This error is also
     * returned when the digital signature is missing, but it's required.
     */
    int WRONG_SIGNATURE = 5;
    /**
     * The provided data is in wrong format. This error code is typically
     * returned when decoding of important parameter failed. For example,
     * if BASE64 encoded value is in wrong format.
     */
    int WRONG_DATA = 6;
    /**
     * The encryption or decryption failed. Whatever that means it's usually
     * very wrong and the UI response depends on what method did you call.
     * Typically, you have to perform retry or restart for the whole process.
     */
    int ENCRYPTION = 7;
    /**
     * The operation requires a signature key that is not available in
     * session's persistent data. For example, if you request a signature
     * calculation with biometric factor but the biometry is not configured
     * in the session.
     */
    int MISSING_REQUESTED_FACTOR = 8;
    /**
     * The operation has a mandatory set of signature factor keys but you
     * don't provide some.
     */
    int MISSING_REQUIRED_FACTOR = 9;
    /**
     * The operation failed on general failure. This type of error is typically
     * returned when underlying implementation fails. For example, if PRNG
     * generator could not produce a sequence of bytes.
     */
    int GENERAL_FAILURE = 10;
}
