import {
  AlertDialogBoxComponent
} from "./chunk-VKBN276O.js";
import {
  AuthenticationService
} from "./chunk-W4QJXU5B.js";
import {
  ShieldService
} from "./chunk-CFULGL53.js";
import {
  CustomerService
} from "./chunk-XQUGZOJS.js";
import {
  Sec
} from "./chunk-LEM5WUQO.js";
import {
  SessionTimeoutService
} from "./chunk-C42OSM34.js";
import {
  CommonSharedService
} from "./chunk-XOSM6WIX.js";
import {
  takeUntilDestroyed
} from "./chunk-2VCRU2OV.js";
import {
  CommonService
} from "./chunk-XSB52M7Q.js";
import {
  AlertMessageComponenent
} from "./chunk-EAZ5CENI.js";
import {
  AlertComponent,
  AlertService,
  AppSettings,
  SharedModule
} from "./chunk-IXIAINKX.js";
import {
  ActivatedRoute,
  Router
} from "./chunk-L2TX3H2Y.js";
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogActions,
  MatDialogClose,
  MatDialogContent,
  MatDialogRef,
  MatDialogTitle,
  MatSnackBar,
  TranslateModule,
  TranslatePipe,
  TranslateService,
  environment
} from "./chunk-L5HWXGQY.js";
import {
  MatButton,
  MatError,
  MatFormField,
  MatHint,
  MatIcon,
  MatIconButton,
  MatInput,
  MatLabel,
  MatPrefix,
  MatSuffix
} from "./chunk-K6KYGI4I.js";
import {
  CommonModule,
  Component,
  DefaultValueAccessor,
  DestroyRef,
  FormBuilder,
  FormControlName,
  FormGroupDirective,
  FormsModule,
  Inject,
  Injectable,
  MaxLengthValidator,
  NgControlStatus,
  NgControlStatusGroup,
  NgIf,
  NgZone,
  PatternValidator,
  ReactiveFormsModule,
  UntypedFormBuilder,
  Validators,
  ViewChild,
  __async,
  __spreadValues,
  first,
  setClassMetadata,
  ɵNgNoValidate,
  ɵsetClassDebugInfo,
  ɵɵadvance,
  ɵɵattribute,
  ɵɵdefineComponent,
  ɵɵdefineInjectable,
  ɵɵdirectiveInject,
  ɵɵelement,
  ɵɵelementEnd,
  ɵɵelementStart,
  ɵɵgetCurrentView,
  ɵɵlistener,
  ɵɵloadQuery,
  ɵɵnextContext,
  ɵɵpipe,
  ɵɵpipeBind1,
  ɵɵproperty,
  ɵɵqueryRefresh,
  ɵɵresetView,
  ɵɵrestoreView,
  ɵɵsanitizeUrl,
  ɵɵtemplate,
  ɵɵtext,
  ɵɵtextInterpolate,
  ɵɵtextInterpolate1,
  ɵɵviewQuery
} from "./chunk-DMFUQV5T.js";

// src/app/pages/login/reset-password/reset-password.component.ts
function ResetPasswordComponent_mat_error_11_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1("", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.PASSWORD_REQUIRED"), " ");
  }
}
function ResetPasswordComponent_mat_error_12_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.MINIMUM_REQUIRED"));
  }
}
function ResetPasswordComponent_mat_error_20_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.CONFIRMPASS_REQUIRED"));
  }
}
function ResetPasswordComponent_div_21_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "div", 11);
    \u0275\u0275text(1, " New password and confirm password do not match.\n");
    \u0275\u0275elementEnd();
  }
}
var ResetPasswordComponent = class _ResetPasswordComponent {
  constructor(dialog, snackBar, authenticationService, destroyRef, fb, dialogRef, data) {
    this.dialog = dialog;
    this.snackBar = snackBar;
    this.authenticationService = authenticationService;
    this.destroyRef = destroyRef;
    this.fb = fb;
    this.dialogRef = dialogRef;
    this.data = data;
    this.submitted = false;
    this.hidePassword = true;
    this.hideNewPassword = true;
    this.hideConfirmPassword = true;
    this.forgotForm = this.fb.group({
      newPassword: ["", [Validators.required, Validators.minLength(6)]],
      confirmPassword: ["", Validators.required]
    }, { validator: this.passwordMatchValidator });
  }
  passwordMatchValidator(form) {
    const newPwd = form.get("newPassword")?.value;
    const confirmPwd = form.get("confirmPassword")?.value;
    return newPwd === confirmPwd ? null : { mismatch: true };
  }
  displayMessage(message, type) {
    const dialogRef = this.dialog.open(AlertMessageComponenent, {
      width: "30%",
      data: { message, type }
    });
  }
  submitnew() {
    this.submitted = true;
    if (this.forgotForm.invalid) {
      return;
    }
    const params = {
      UserId: this.data.userId,
      Newpassword: this.forgotForm.get("newPassword")?.value
    };
    this.authenticationService.resetPassword(params).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (res) => {
        if (res?.Success) {
          this.displayMessage(res.Message, "Success");
          this.dialogRef.close();
        } else {
          this.displayMessage(res.Message, "Error");
        }
        this.forgotForm.reset();
        this.submitted = false;
      },
      error: () => {
        this.displayMessage("Error changing password", "Error");
        this.forgotForm.reset();
        this.submitted = false;
      }
    });
  }
  static {
    this.\u0275fac = function ResetPasswordComponent_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _ResetPasswordComponent)(\u0275\u0275directiveInject(MatDialog), \u0275\u0275directiveInject(MatSnackBar), \u0275\u0275directiveInject(AuthenticationService), \u0275\u0275directiveInject(DestroyRef), \u0275\u0275directiveInject(FormBuilder), \u0275\u0275directiveInject(MatDialogRef), \u0275\u0275directiveInject(MAT_DIALOG_DATA));
    };
  }
  static {
    this.\u0275cmp = /* @__PURE__ */ \u0275\u0275defineComponent({ type: _ResetPasswordComponent, selectors: [["app-change-password"]], standalone: false, decls: 27, vars: 13, consts: [["mat-dialog-title", ""], ["autocomplete", "off", 3, "formGroup"], [1, "w-100"], ["matInput", "", "formControlName", "newPassword", "maxlength", "8", "autocomplete", "new-password", 3, "type"], ["mat-icon-button", "", "matSuffix", "", "type", "button", 3, "click"], [4, "ngIf"], ["matInput", "", "formControlName", "confirmPassword", "maxlength", "8", "autocomplete", "new-password", 3, "type"], ["class", "error", 4, "ngIf"], ["align", "end"], ["mat-button", "", "mat-dialog-close", "", 1, "btd-close"], ["mat-raised-button", "", "color", "primary", 3, "click"], [1, "error"]], template: function ResetPasswordComponent_Template(rf, ctx) {
      if (rf & 1) {
        \u0275\u0275elementStart(0, "h2", 0);
        \u0275\u0275text(1, "Reset Password");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(2, "mat-dialog-content")(3, "form", 1)(4, "mat-form-field", 2)(5, "mat-label");
        \u0275\u0275text(6, "New Password");
        \u0275\u0275elementEnd();
        \u0275\u0275element(7, "input", 3);
        \u0275\u0275elementStart(8, "button", 4);
        \u0275\u0275listener("click", function ResetPasswordComponent_Template_button_click_8_listener() {
          return ctx.hideNewPassword = !ctx.hideNewPassword;
        });
        \u0275\u0275elementStart(9, "mat-icon");
        \u0275\u0275text(10);
        \u0275\u0275elementEnd()();
        \u0275\u0275template(11, ResetPasswordComponent_mat_error_11_Template, 3, 3, "mat-error", 5)(12, ResetPasswordComponent_mat_error_12_Template, 3, 3, "mat-error", 5);
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(13, "mat-form-field", 2)(14, "mat-label");
        \u0275\u0275text(15, "Confirm New Password");
        \u0275\u0275elementEnd();
        \u0275\u0275element(16, "input", 6);
        \u0275\u0275elementStart(17, "button", 4);
        \u0275\u0275listener("click", function ResetPasswordComponent_Template_button_click_17_listener() {
          return ctx.hideConfirmPassword = !ctx.hideConfirmPassword;
        });
        \u0275\u0275elementStart(18, "mat-icon");
        \u0275\u0275text(19);
        \u0275\u0275elementEnd()();
        \u0275\u0275template(20, ResetPasswordComponent_mat_error_20_Template, 3, 3, "mat-error", 5);
        \u0275\u0275elementEnd();
        \u0275\u0275template(21, ResetPasswordComponent_div_21_Template, 2, 0, "div", 7);
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(22, "mat-dialog-actions", 8)(23, "button", 9);
        \u0275\u0275text(24, "Cancel");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(25, "button", 10);
        \u0275\u0275listener("click", function ResetPasswordComponent_Template_button_click_25_listener() {
          return ctx.submitnew();
        });
        \u0275\u0275text(26, "Confirm");
        \u0275\u0275elementEnd()();
      }
      if (rf & 2) {
        \u0275\u0275advance(3);
        \u0275\u0275property("formGroup", ctx.forgotForm);
        \u0275\u0275advance(4);
        \u0275\u0275property("type", ctx.hideNewPassword ? "password" : "text");
        \u0275\u0275advance();
        \u0275\u0275attribute("aria-label", "Toggle password visibility")("aria-pressed", !ctx.hideNewPassword);
        \u0275\u0275advance(2);
        \u0275\u0275textInterpolate(ctx.hideNewPassword ? "visibility_off" : "visibility");
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.newPassword.errors == null ? null : ctx.forgotForm.controls.newPassword.errors.required);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.newPassword.hasError("minlength"));
        \u0275\u0275advance(4);
        \u0275\u0275property("type", ctx.hideConfirmPassword ? "password" : "text");
        \u0275\u0275advance();
        \u0275\u0275attribute("aria-label", "Toggle password visibility")("aria-pressed", !ctx.hideConfirmPassword);
        \u0275\u0275advance(2);
        \u0275\u0275textInterpolate(ctx.hideConfirmPassword ? "visibility_off" : "visibility");
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.confirmPassword.errors == null ? null : ctx.forgotForm.controls.confirmPassword.errors.required);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", (ctx.forgotForm.errors == null ? null : ctx.forgotForm.errors.mismatch) && ctx.submitted);
      }
    }, dependencies: [NgIf, MatDialogClose, MatDialogTitle, MatDialogActions, MatDialogContent, \u0275NgNoValidate, DefaultValueAccessor, NgControlStatus, NgControlStatusGroup, MaxLengthValidator, MatButton, MatIconButton, MatInput, MatFormField, MatLabel, MatError, MatSuffix, FormGroupDirective, FormControlName, MatIcon, TranslatePipe], styles: ["\n\n.error[_ngcontent-%COMP%] {\n  margin-top: 1rem;\n  color: red;\n  font-size: 0.85rem;\n  margin-top: -0.5rem;\n  margin-bottom: 1rem;\n}\n@media (max-width: 600px) {\n  [_nghost-%COMP%] {\n    padding: 0.5rem;\n  }\n  mat-dialog-container[_ngcontent-%COMP%] {\n    width: 90vw !important;\n  }\n}"] });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ResetPasswordComponent, [{
    type: Component,
    args: [{ selector: "app-change-password", standalone: false, template: `<h2 mat-dialog-title>Reset Password</h2>\r
<mat-dialog-content>\r
  <form [formGroup]="forgotForm" autocomplete="off">\r
    <mat-form-field class="w-100">\r
  <mat-label>New Password</mat-label>\r
  <input matInput\r
         [type]="hideNewPassword ? 'password' : 'text'"\r
         formControlName="newPassword" maxlength="8"\r
         autocomplete="new-password" />\r
\r
  <button mat-icon-button\r
          matSuffix\r
          (click)="hideNewPassword = !hideNewPassword"\r
          [attr.aria-label]="'Toggle password visibility'"\r
          [attr.aria-pressed]="!hideNewPassword"\r
          type="button">\r
    <mat-icon>{{ hideNewPassword ? 'visibility_off' : 'visibility' }}</mat-icon>\r
  </button>\r
<mat-error *ngIf="forgotForm.controls.newPassword.errors?.required">{{ 'LOGIN.FORM.ERROR.PASSWORD_REQUIRED' | translate }}\r
                                </mat-error>\r
                                <mat-error *ngIf="forgotForm.controls.newPassword.hasError('minlength')">{{ 'LOGIN.FORM.ERROR.MINIMUM_REQUIRED' | translate }}</mat-error>\r
                            </mat-form-field>\r
\r
   <mat-form-field class="w-100">\r
  <mat-label>Confirm New Password</mat-label>\r
  <input matInput\r
         [type]="hideConfirmPassword ? 'password' : 'text'"\r
         formControlName="confirmPassword" maxlength="8"\r
         autocomplete="new-password" />\r
\r
  <button mat-icon-button\r
          matSuffix\r
          (click)="hideConfirmPassword = !hideConfirmPassword"\r
          [attr.aria-label]="'Toggle password visibility'"\r
          [attr.aria-pressed]="!hideConfirmPassword"\r
          type="button">\r
    <mat-icon>{{ hideConfirmPassword ? 'visibility_off' : 'visibility' }}</mat-icon>\r
  </button>\r
  <mat-error *ngIf="forgotForm.controls.confirmPassword.errors?.required">{{ 'LOGIN.FORM.ERROR.CONFIRMPASS_REQUIRED' | translate }}</mat-error>\r
</mat-form-field>\r
\r
 <div *ngIf="forgotForm.errors?.mismatch && submitted" class="error">\r
  New password and confirm password do not match.\r
</div>\r
  </form>\r
</mat-dialog-content>\r
<mat-dialog-actions align="end">\r
  <button mat-button mat-dialog-close class="btd-close">Cancel</button>\r
  <button mat-raised-button color="primary" (click)="submitnew()">Confirm</button>\r
</mat-dialog-actions>\r
`, styles: ["/* src/app/pages/login/reset-password/reset-password.component.scss */\n.error {\n  margin-top: 1rem;\n  color: red;\n  font-size: 0.85rem;\n  margin-top: -0.5rem;\n  margin-bottom: 1rem;\n}\n@media (max-width: 600px) {\n  :host {\n    padding: 0.5rem;\n  }\n  mat-dialog-container {\n    width: 90vw !important;\n  }\n}\n"] }]
  }], () => [{ type: MatDialog }, { type: MatSnackBar }, { type: AuthenticationService }, { type: DestroyRef }, { type: FormBuilder }, { type: MatDialogRef }, { type: void 0, decorators: [{
    type: Inject,
    args: [MAT_DIALOG_DATA]
  }] }], null);
})();
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && \u0275setClassDebugInfo(ResetPasswordComponent, { className: "ResetPasswordComponent", filePath: "src/app/pages/login/reset-password/reset-password.component.ts", lineNumber: 17 });
})();

// src/app/pages/login/forgot-password/forgot-password.component.ts
function ForgotPasswordComponent_mat_error_10_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error", 13);
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.USERID_REQUIRED"), " ");
  }
}
function ForgotPasswordComponent_mat_error_11_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error", 14);
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.VALID_USERID"), " ");
  }
}
function ForgotPasswordComponent_mat_error_12_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error", 15);
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.INVALID_USERID"), " ");
  }
}
function ForgotPasswordComponent_form_13_mat_error_7_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error", 27);
    \u0275\u0275text(1, " OTP is required ");
    \u0275\u0275elementEnd();
  }
}
function ForgotPasswordComponent_form_13_Template(rf, ctx) {
  if (rf & 1) {
    const _r1 = \u0275\u0275getCurrentView();
    \u0275\u0275elementStart(0, "form", 16)(1, "div", 17)(2, "div", 18)(3, "mat-form-field", 19)(4, "mat-label", 20);
    \u0275\u0275text(5, "Enter OTP");
    \u0275\u0275elementEnd();
    \u0275\u0275elementStart(6, "input", 21);
    \u0275\u0275listener("keypress", function ForgotPasswordComponent_form_13_Template_input_keypress_6_listener($event) {
      \u0275\u0275restoreView(_r1);
      const ctx_r1 = \u0275\u0275nextContext();
      return \u0275\u0275resetView(ctx_r1.onKeyPresspol($event));
    });
    \u0275\u0275elementEnd();
    \u0275\u0275template(7, ForgotPasswordComponent_form_13_mat_error_7_Template, 2, 0, "mat-error", 22);
    \u0275\u0275elementEnd();
    \u0275\u0275elementStart(8, "button", 23);
    \u0275\u0275listener("click", function ForgotPasswordComponent_form_13_Template_button_click_8_listener() {
      \u0275\u0275restoreView(_r1);
      const ctx_r1 = \u0275\u0275nextContext();
      return \u0275\u0275resetView(ctx_r1.verifyOtp());
    });
    \u0275\u0275text(9, " Verify OTP ");
    \u0275\u0275elementEnd()();
    \u0275\u0275elementStart(10, "div", 24)(11, "button", 25);
    \u0275\u0275listener("click", function ForgotPasswordComponent_form_13_Template_button_click_11_listener() {
      \u0275\u0275restoreView(_r1);
      const ctx_r1 = \u0275\u0275nextContext();
      return \u0275\u0275resetView(ctx_r1.resendOtp());
    });
    \u0275\u0275text(12, "Resend OTP");
    \u0275\u0275elementEnd();
    \u0275\u0275elementStart(13, "button", 26);
    \u0275\u0275text(14, "Cancel");
    \u0275\u0275elementEnd()()()();
  }
  if (rf & 2) {
    const ctx_r1 = \u0275\u0275nextContext();
    \u0275\u0275property("formGroup", ctx_r1.otpForm);
    \u0275\u0275advance(7);
    \u0275\u0275property("ngIf", ctx_r1.otpForm.controls.otp.errors == null ? null : ctx_r1.otpForm.controls.otp.errors.required);
  }
}
function ForgotPasswordComponent_mat_dialog_actions_14_Template(rf, ctx) {
  if (rf & 1) {
    const _r3 = \u0275\u0275getCurrentView();
    \u0275\u0275elementStart(0, "mat-dialog-actions", 28)(1, "button", 29);
    \u0275\u0275listener("click", function ForgotPasswordComponent_mat_dialog_actions_14_Template_button_click_1_listener() {
      \u0275\u0275restoreView(_r3);
      const ctx_r1 = \u0275\u0275nextContext();
      return \u0275\u0275resetView(ctx_r1.submit());
    });
    \u0275\u0275text(2, "Confirm");
    \u0275\u0275elementEnd();
    \u0275\u0275elementStart(3, "button", 30);
    \u0275\u0275text(4, "Cancel");
    \u0275\u0275elementEnd()();
  }
}
var ForgotPasswordComponent = class _ForgotPasswordComponent {
  constructor(snackBar, dialog, appSettings, fb, authenticationService, destroyRef, dialogRef) {
    this.snackBar = snackBar;
    this.dialog = dialog;
    this.appSettings = appSettings;
    this.fb = fb;
    this.authenticationService = authenticationService;
    this.destroyRef = destroyRef;
    this.dialogRef = dialogRef;
    this.submitted = false;
    this.hidePassword = true;
    this.hideNewPassword = true;
    this.hideConfirmPassword = true;
    this.otpSent = false;
    this.countdown = 600;
    this.settings = this.appSettings.settings;
    this.forgotForm = this.fb.group({
      userId: ["", Validators.required]
      // currentPassword: ['', Validators.required],
      // newPassword: ['', [Validators.required, Validators.minLength(6)]],
      // confirmPassword: ['', Validators.required]
    }, { validator: this.passwordMatchValidator });
    this.otpForm = this.fb.group({
      otp: ["", Validators.required]
    });
  }
  passwordMatchValidator(form) {
    const newPwd = form.get("newPassword")?.value;
    const confirmPwd = form.get("confirmPassword")?.value;
    return newPwd === confirmPwd ? null : { mismatch: true };
  }
  submit() {
    if (this.forgotForm.invalid)
      return;
    this.settings.loadingSpinner = true;
    const params = {
      UserId: this.forgotForm.get("userId")?.value
    };
    this.authenticationService.forgotpassword(params).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (res) => {
        if (res?.Sent) {
          this.settings.loadingSpinner = false;
          this.displayMessage(res.Message, "Success");
          this.otpSent = true;
          this.startCountdown();
          this.forgotForm.controls["userId"].disable();
        } else {
          this.settings.loadingSpinner = false;
          this.displayMessage("Failed to send OTP", "Alert");
        }
      },
      error: () => {
        this.settings.loadingSpinner = false;
        this.displayMessage("Something went wrong. Please try again.", "Alert");
      }
    });
  }
  verifyOtp() {
    if (this.otpForm.invalid)
      return;
    this.settings.loadingSpinner = true;
    const params = {
      UserId: this.forgotForm.get("userId")?.value,
      Otp: this.otpForm.get("otp")?.value
    };
    this.authenticationService.verifyOTP(params).subscribe({
      next: (res) => {
        this.settings.loadingSpinner = false;
        if (res?.Success) {
          this.snackBar.open(res.Message, "Close", { duration: 1500, horizontalPosition: "center", verticalPosition: "top" });
          this.dialogRef.close();
          setTimeout(() => {
            this.dialogRef.close();
            this.dialog.open(ResetPasswordComponent, {
              width: "400px",
              data: { userId: params.UserId }
            });
          }, 500);
        } else {
          this.displayMessage(res?.Message || "Invalid OTP", "Error");
          this.otpForm.reset();
        }
      },
      error: () => {
        this.settings.loadingSpinner = false;
        this.displayMessage("Something went wrong. Please try again.", "Error");
      }
    });
  }
  onKeyPresspol(event) {
    const allowedKeys = /^[0-9]$/;
    if (!allowedKeys.test(event.key)) {
      event.preventDefault();
    }
  }
  displayMessage(message, type) {
    const dialogRef = this.dialog.open(AlertMessageComponenent, {
      width: "30%",
      data: { message, type }
    });
  }
  resendOtp() {
    if (this.forgotForm.invalid)
      return;
    this.settings.loadingSpinner = true;
    const params = {
      UserId: this.forgotForm.get("userId")?.value
    };
    this.authenticationService.forgotpassword(params).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (res) => {
        this.settings.loadingSpinner = false;
        if (res?.Sent) {
          this.displayMessage("OTP resend successfully", "Success");
          this.otpForm.reset();
          this.startCountdown();
        } else {
          this.displayMessage("Failed to resend OTP", "Error");
        }
      },
      error: () => {
        this.settings.loadingSpinner = false;
        this.displayMessage("Something went wrong. Please try again.", "Error");
      }
    });
  }
  startCountdown() {
    this.countdown = 600;
    clearInterval(this.interval);
    this.interval = setInterval(() => {
      this.countdown--;
      if (this.countdown <= 0)
        clearInterval(this.interval);
    }, 1e3);
  }
  static {
    this.\u0275fac = function ForgotPasswordComponent_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _ForgotPasswordComponent)(\u0275\u0275directiveInject(MatSnackBar), \u0275\u0275directiveInject(MatDialog), \u0275\u0275directiveInject(AppSettings), \u0275\u0275directiveInject(FormBuilder), \u0275\u0275directiveInject(AuthenticationService), \u0275\u0275directiveInject(DestroyRef), \u0275\u0275directiveInject(MatDialogRef));
    };
  }
  static {
    this.\u0275cmp = /* @__PURE__ */ \u0275\u0275defineComponent({ type: _ForgotPasswordComponent, selectors: [["app-forgot-password"]], standalone: false, decls: 15, vars: 6, consts: [["mat-dialog-title", "", "id", "forgot-password-title", "data-testid", "forgot-password-title"], ["id", "forgot-password-content", "data-testid", "forgot-password-content"], ["autocomplete", "off", "id", "forgot-password-form", "data-testid", "forgot-password-form", 3, "formGroup"], ["type", "text", "name", "fakeuser", "autocomplete", "username", 2, "display", "none"], ["type", "password", "name", "fakepass", "autocomplete", "new-password", 2, "display", "none"], ["appearance", "outline", "id", "forgot-password-userid-field", "data-testid", "forgot-password-userid-field", 1, "w-100", "ml-mt-2"], ["id", "forgot-password-userid-label", "data-testid", "forgot-password-userid-label"], ["matInput", "", "formControlName", "userId", "autocomplete", "off", "maxlength", "6", "id", "input-forgot-password-userid", "data-testid", "input-forgot-password-userid", 3, "keypress"], ["id", "error-forgot-password-userid-required", "data-testid", "error-forgot-password-userid-required", 4, "ngIf"], ["id", "error-forgot-password-userid-pattern", "data-testid", "error-forgot-password-userid-pattern", 4, "ngIf"], ["id", "error-forgot-password-userid-invalid", "data-testid", "error-forgot-password-userid-invalid", 4, "ngIf"], ["autocomplete", "off", "id", "forgot-password-otp-form", "data-testid", "forgot-password-otp-form", 3, "formGroup", 4, "ngIf"], ["class", "ml-d-flex ml-justify-content-end ml-gap-2 w-100", "id", "forgot-password-main-actions", "data-testid", "forgot-password-main-actions", 4, "ngIf"], ["id", "error-forgot-password-userid-required", "data-testid", "error-forgot-password-userid-required"], ["id", "error-forgot-password-userid-pattern", "data-testid", "error-forgot-password-userid-pattern"], ["id", "error-forgot-password-userid-invalid", "data-testid", "error-forgot-password-userid-invalid"], ["autocomplete", "off", "id", "forgot-password-otp-form", "data-testid", "forgot-password-otp-form", 3, "formGroup"], ["id", "forgot-password-otp-container", "data-testid", "forgot-password-otp-container", 1, "ml-d-flex", "ml-flex-column", "ml-gap-2"], ["id", "forgot-password-otp-input-section", "data-testid", "forgot-password-otp-input-section", 1, "ml-d-flex", "ml-flex-sm-row", "ml-align-items-center", "ml-gap-2"], ["appearance", "outline", "id", "forgot-password-otp-field", "data-testid", "forgot-password-otp-field", 1, "w-100", "ml-flex-grow-1"], ["id", "forgot-password-otp-label", "data-testid", "forgot-password-otp-label"], ["matInput", "", "formControlName", "otp", "maxlength", "6", "id", "input-forgot-password-otp", "data-testid", "input-forgot-password-otp", 3, "keypress"], ["id", "error-forgot-password-otp-required", "data-testid", "error-forgot-password-otp-required", 4, "ngIf"], ["mat-raised-button", "", "color", "primary", "id", "btn-forgot-password-verify-otp", "data-testid", "btn-forgot-password-verify-otp", 1, "ml-flex-shrink-0", 3, "click"], ["id", "forgot-password-otp-actions", "data-testid", "forgot-password-otp-actions", 1, "ml-d-flex", "ml-gap-2", "ml-mt-2"], ["mat-raised-button", "", "color", "primary", "id", "btn-forgot-password-resend-otp", "data-testid", "btn-forgot-password-resend-otp", 1, "btn-small", 3, "click"], ["mat-button", "", "mat-dialog-close", "", "id", "btn-forgot-password-otp-cancel", "data-testid", "btn-forgot-password-otp-cancel", 1, "btd-close"], ["id", "error-forgot-password-otp-required", "data-testid", "error-forgot-password-otp-required"], ["id", "forgot-password-main-actions", "data-testid", "forgot-password-main-actions", 1, "ml-d-flex", "ml-justify-content-end", "ml-gap-2", "w-100"], ["mat-raised-button", "", "color", "primary", "id", "btn-forgot-password-confirm", "data-testid", "btn-forgot-password-confirm", 3, "click"], ["mat-button", "", "mat-dialog-close", "", "id", "btn-forgot-password-cancel", "data-testid", "btn-forgot-password-cancel", 1, "btd-close"]], template: function ForgotPasswordComponent_Template(rf, ctx) {
      if (rf & 1) {
        \u0275\u0275elementStart(0, "h2", 0);
        \u0275\u0275text(1, "Forgot Password");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(2, "mat-dialog-content", 1)(3, "form", 2);
        \u0275\u0275element(4, "input", 3)(5, "input", 4);
        \u0275\u0275elementStart(6, "mat-form-field", 5)(7, "mat-label", 6);
        \u0275\u0275text(8, "User ID");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(9, "input", 7);
        \u0275\u0275listener("keypress", function ForgotPasswordComponent_Template_input_keypress_9_listener($event) {
          return ctx.onKeyPresspol($event);
        });
        \u0275\u0275elementEnd();
        \u0275\u0275template(10, ForgotPasswordComponent_mat_error_10_Template, 3, 3, "mat-error", 8)(11, ForgotPasswordComponent_mat_error_11_Template, 3, 3, "mat-error", 9)(12, ForgotPasswordComponent_mat_error_12_Template, 3, 3, "mat-error", 10);
        \u0275\u0275elementEnd()();
        \u0275\u0275template(13, ForgotPasswordComponent_form_13_Template, 15, 2, "form", 11);
        \u0275\u0275elementEnd();
        \u0275\u0275template(14, ForgotPasswordComponent_mat_dialog_actions_14_Template, 5, 0, "mat-dialog-actions", 12);
      }
      if (rf & 2) {
        \u0275\u0275advance(3);
        \u0275\u0275property("formGroup", ctx.forgotForm);
        \u0275\u0275advance(7);
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.userId.errors == null ? null : ctx.forgotForm.controls.userId.errors.required);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.userId.errors == null ? null : ctx.forgotForm.controls.userId.errors.pattern);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.forgotForm.controls.userId.hasError("invalidEmail"));
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.otpSent);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", !ctx.otpSent);
      }
    }, dependencies: [NgIf, MatDialogClose, MatDialogTitle, MatDialogActions, MatDialogContent, \u0275NgNoValidate, DefaultValueAccessor, NgControlStatus, NgControlStatusGroup, MaxLengthValidator, MatButton, MatInput, MatFormField, MatLabel, MatError, FormGroupDirective, FormControlName, TranslatePipe], styles: ["\n\n.error[_ngcontent-%COMP%] {\n  color: red;\n  font-size: 0.85rem;\n  margin-top: -0.5rem;\n  margin-bottom: 1rem;\n}\n@media (max-width: 600px) {\n  [_nghost-%COMP%] {\n    padding: 0.5rem;\n  }\n  mat-dialog-container[_ngcontent-%COMP%] {\n    width: 90vw !important;\n  }\n}\n.btn-small[_ngcontent-%COMP%] {\n  min-width: 40px !important;\n  padding: 0 8px;\n}"] });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ForgotPasswordComponent, [{
    type: Component,
    args: [{ selector: "app-forgot-password", standalone: false, template: `<h2 mat-dialog-title id="forgot-password-title" data-testid="forgot-password-title">Forgot Password</h2>\r
<mat-dialog-content id="forgot-password-content" data-testid="forgot-password-content">\r
  <!-- User ID form -->\r
  <form [formGroup]="forgotForm" autocomplete="off" id="forgot-password-form" data-testid="forgot-password-form">\r
    <input type="text" name="fakeuser" autocomplete="username" style="display:none">\r
    <input type="password" name="fakepass" autocomplete="new-password" style="display:none">\r
\r
    <mat-form-field class="w-100 ml-mt-2" appearance="outline" id="forgot-password-userid-field" data-testid="forgot-password-userid-field">\r
      <mat-label id="forgot-password-userid-label" data-testid="forgot-password-userid-label">User ID</mat-label>\r
      <input matInput formControlName="userId" autocomplete="off" maxlength="6" (keypress)="onKeyPresspol($event)" id="input-forgot-password-userid" data-testid="input-forgot-password-userid" />\r
      <mat-error *ngIf="forgotForm.controls.userId.errors?.required" id="error-forgot-password-userid-required" data-testid="error-forgot-password-userid-required">\r
        {{ 'LOGIN.FORM.ERROR.USERID_REQUIRED' | translate }}\r
      </mat-error>\r
      <mat-error *ngIf="forgotForm.controls.userId.errors?.pattern" id="error-forgot-password-userid-pattern" data-testid="error-forgot-password-userid-pattern">\r
        {{ 'LOGIN.FORM.ERROR.VALID_USERID' | translate }}\r
      </mat-error>\r
      <mat-error *ngIf="forgotForm.controls.userId.hasError('invalidEmail')" id="error-forgot-password-userid-invalid" data-testid="error-forgot-password-userid-invalid">\r
        {{ 'LOGIN.FORM.ERROR.INVALID_USERID' | translate }}\r
      </mat-error>\r
    </mat-form-field>\r
  </form>\r
\r
  <!-- OTP form -->\r
  <form [formGroup]="otpForm" *ngIf="otpSent" autocomplete="off" id="forgot-password-otp-form" data-testid="forgot-password-otp-form">\r
    <div class="ml-d-flex ml-flex-column ml-gap-2" id="forgot-password-otp-container" data-testid="forgot-password-otp-container">\r
      <!-- OTP input + Verify button -->\r
      <div class="ml-d-flex ml-flex-sm-row ml-align-items-center ml-gap-2" id="forgot-password-otp-input-section" data-testid="forgot-password-otp-input-section">\r
        <mat-form-field class="w-100 ml-flex-grow-1" appearance="outline" id="forgot-password-otp-field" data-testid="forgot-password-otp-field">\r
          <mat-label id="forgot-password-otp-label" data-testid="forgot-password-otp-label">Enter OTP</mat-label>\r
          <input matInput formControlName="otp" maxlength="6" (keypress)="onKeyPresspol($event)" id="input-forgot-password-otp" data-testid="input-forgot-password-otp" />\r
          <mat-error *ngIf="otpForm.controls.otp.errors?.required" id="error-forgot-password-otp-required" data-testid="error-forgot-password-otp-required">\r
            OTP is required\r
          </mat-error>\r
        </mat-form-field>\r
\r
        <button mat-raised-button color="primary" (click)="verifyOtp()" class="ml-flex-shrink-0" id="btn-forgot-password-verify-otp" data-testid="btn-forgot-password-verify-otp">\r
          Verify OTP\r
        </button>\r
      </div>\r
\r
      \r
      <div class="ml-d-flex ml-gap-2 ml-mt-2" id="forgot-password-otp-actions" data-testid="forgot-password-otp-actions">\r
        <button mat-raised-button color="primary" class="btn-small" (click)="resendOtp()" id="btn-forgot-password-resend-otp" data-testid="btn-forgot-password-resend-otp">Resend OTP</button>\r
        <button class="btd-close" mat-button mat-dialog-close id="btn-forgot-password-otp-cancel" data-testid="btn-forgot-password-otp-cancel">Cancel</button>\r
      </div>\r
    </div>\r
  </form>\r
</mat-dialog-content>\r
\r
\r
<mat-dialog-actions class="ml-d-flex ml-justify-content-end ml-gap-2 w-100" *ngIf="!otpSent" id="forgot-password-main-actions" data-testid="forgot-password-main-actions">\r
  <button mat-raised-button color="primary" (click)="submit()" id="btn-forgot-password-confirm" data-testid="btn-forgot-password-confirm">Confirm</button>\r
  <button class="btd-close" mat-button mat-dialog-close id="btn-forgot-password-cancel" data-testid="btn-forgot-password-cancel">Cancel</button>\r
</mat-dialog-actions>\r
`, styles: ["/* src/app/pages/login/forgot-password/forgot-password.component.scss */\n.error {\n  color: red;\n  font-size: 0.85rem;\n  margin-top: -0.5rem;\n  margin-bottom: 1rem;\n}\n@media (max-width: 600px) {\n  :host {\n    padding: 0.5rem;\n  }\n  mat-dialog-container {\n    width: 90vw !important;\n  }\n}\n.btn-small {\n  min-width: 40px !important;\n  padding: 0 8px;\n}\n"] }]
  }], () => [{ type: MatSnackBar }, { type: MatDialog }, { type: AppSettings }, { type: FormBuilder }, { type: AuthenticationService }, { type: DestroyRef }, { type: MatDialogRef }], null);
})();
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && \u0275setClassDebugInfo(ForgotPasswordComponent, { className: "ForgotPasswordComponent", filePath: "src/app/pages/login/forgot-password/forgot-password.component.ts", lineNumber: 23 });
})();

// src/app/services/branding.service.ts
var BrandingService = class _BrandingService {
  constructor() {
    this.defaultConfig = {
      logo: "assets/img/logo2.png",
      brandLogo: "assets/img/top.png",
      decorativeImage: "assets/img/bottom.png",
      companyName: "MSME-LOS"
    };
  }
  getBrandingConfig() {
    const saved = localStorage.getItem("brandingConfig");
    return saved ? __spreadValues(__spreadValues({}, this.defaultConfig), JSON.parse(saved)) : this.defaultConfig;
  }
  updateBranding(config) {
    const current = this.getBrandingConfig();
    const updated = __spreadValues(__spreadValues({}, current), config);
    localStorage.setItem("brandingConfig", JSON.stringify(updated));
  }
  uploadImage(file) {
    return new Promise((resolve, reject) => {
      if (!file.type.startsWith("image/")) {
        reject("Please select an image file");
        return;
      }
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject("Error reading file");
      reader.readAsDataURL(file);
    });
  }
  resetToDefault() {
    localStorage.removeItem("brandingConfig");
  }
  static {
    this.\u0275fac = function BrandingService_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _BrandingService)();
    };
  }
  static {
    this.\u0275prov = /* @__PURE__ */ \u0275\u0275defineInjectable({ token: _BrandingService, factory: _BrandingService.\u0275fac, providedIn: "root" });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(BrandingService, [{
    type: Injectable,
    args: [{
      providedIn: "root"
    }]
  }], null, null);
})();

// src/app/pages/login/login.component.ts
var _c0 = ["captchaCanvas"];
function LoginComponent_mat_error_34_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.USERID_REQUIRED"), " ");
  }
}
function LoginComponent_mat_error_46_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.PASSWORD_REQUIRED"), " ");
  }
}
function LoginComponent_mat_error_47_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1);
    \u0275\u0275pipe(2, "translate");
    \u0275\u0275elementEnd();
  }
  if (rf & 2) {
    \u0275\u0275advance();
    \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(2, 1, "LOGIN.FORM.ERROR.PASSWORD_PATTERN"), " ");
  }
}
function LoginComponent_mat_error_61_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-error");
    \u0275\u0275text(1, " CAPTCHA is required ");
    \u0275\u0275elementEnd();
  }
}
function LoginComponent_mat_hint_62_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-hint", 37)(1, "mat-icon", 38);
    \u0275\u0275text(2, "cancel");
    \u0275\u0275elementEnd();
    \u0275\u0275text(3, " CAPTCHA does not match ");
    \u0275\u0275elementEnd();
  }
}
function LoginComponent_mat_hint_63_Template(rf, ctx) {
  if (rf & 1) {
    \u0275\u0275elementStart(0, "mat-hint", 39)(1, "mat-icon", 38);
    \u0275\u0275text(2, "check_circle");
    \u0275\u0275elementEnd();
    \u0275\u0275text(3, " CAPTCHA matched ");
    \u0275\u0275elementEnd();
  }
}
var LoginComponent = class _LoginComponent {
  constructor(zone, dialog, appSettings, fb, router, route, destroyRef, commonService, commonSharedService, secure, authenticationService, alertService, translate, shieldService, addCustomerService, snackBar, brandingService, sessionTimeoutService) {
    this.zone = zone;
    this.dialog = dialog;
    this.appSettings = appSettings;
    this.fb = fb;
    this.router = router;
    this.route = route;
    this.destroyRef = destroyRef;
    this.commonService = commonService;
    this.commonSharedService = commonSharedService;
    this.secure = secure;
    this.authenticationService = authenticationService;
    this.alertService = alertService;
    this.translate = translate;
    this.shieldService = shieldService;
    this.addCustomerService = addCustomerService;
    this.snackBar = snackBar;
    this.brandingService = brandingService;
    this.sessionTimeoutService = sessionTimeoutService;
    this.branchList = [];
    this.captchaText = "";
    this.captchaValid = false;
    this.hidePassword = true;
    this.settings = this.appSettings.settings;
    this.brandingConfig = this.brandingService.getBrandingConfig();
    this.form = this.fb.group({
      "email": [null, Validators.compose([Validators.required])],
      "product": [null, Validators.compose([Validators.required])],
      "password": [null, Validators.compose([Validators.required, Validators.minLength(8)])],
      "captcha": [null, Validators.required]
    });
  }
  openForgotPassword() {
    this.dialog.open(ForgotPasswordComponent, {
      width: "400px",
      hasBackdrop: true,
      backdropClass: "custom-backdrop",
      panelClass: "custom-dialog"
    });
  }
  ngOnInit() {
    this.generateCaptcha();
    this.onload();
    this.loginType = environment.loginType;
    this.form.get("captcha")?.valueChanges.subscribe((value) => {
      this.captchaValid = value === this.captchaText;
    });
  }
  //for testing the new encryption ,hardcoded data
  testMySpecificPayload() {
    return __async(this, null, function* () {
      const myBase64AesKey = "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=";
      const ivB64 = "ranplDEStAIrCwO5";
      const dataB64 = "TEbAoVmGpvQymmQt2kHs3AKCuJ1s07+0/SNCU3G+QMlx3LBlPlR4aSMMMVQKsSG9riZbFwOvZEezQw5fV8Ho2fuF5HegrU1Fg2ts3cFa3wJGI84E0JaT/DTzsUkB/268og46tKmO5Sbh4G8NteHvQjh88pk6CG80X6qo49QtmA==";
      function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
      }
      try {
        const rawKeyBuffer = base64ToArrayBuffer(myBase64AesKey);
        const aesKeyObject = yield crypto.subtle.importKey("raw", rawKeyBuffer, { name: "AES-GCM" }, false, ["decrypt"]);
        const iv = base64ToArrayBuffer(ivB64);
        const encryptedData = base64ToArrayBuffer(dataB64);
        const decryptedData = yield crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKeyObject, encryptedData);
        const decryptedString = new TextDecoder().decode(decryptedData);
      } catch (error) {
      }
    });
  }
  generateCaptcha() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    this.captchaText = Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
    this.drawCaptcha();
    this.captchaValid = false;
    this.form.get("captcha")?.reset();
  }
  drawCaptcha() {
    const canvas = this.canvasRef.nativeElement;
    const ctx = canvas.getContext("2d");
    if (!ctx)
      return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const gradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
    gradient.addColorStop(0, "#f0f4ff");
    gradient.addColorStop(1, "#e8eeff");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < 20; i++) {
      ctx.fillStyle = `rgba(102, 126, 234, ${Math.random() * 0.1})`;
      ctx.beginPath();
      ctx.arc(Math.random() * canvas.width, Math.random() * canvas.height, 1, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.font = "bold 26px Arial";
    ctx.fillStyle = "#667eea";
    ctx.textBaseline = "middle";
    ctx.textAlign = "center";
    const totalWidth = this.captchaText.length * 20;
    const startX = (canvas.width - totalWidth) / 2 + 10;
    let x = startX;
    for (let i = 0; i < this.captchaText.length; i++) {
      ctx.save();
      ctx.translate(x, canvas.height / 2);
      ctx.rotate((Math.random() - 0.5) * 0.3);
      ctx.fillText(this.captchaText[i], 0, 0);
      ctx.restore();
      x += 20;
    }
    for (let i = 0; i < 2; i++) {
      ctx.strokeStyle = `rgba(118, 75, 162, ${Math.random() * 0.3 + 0.2})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(Math.random() * canvas.width, Math.random() * canvas.height);
      ctx.lineTo(Math.random() * canvas.width, Math.random() * canvas.height);
      ctx.stroke();
    }
  }
  onload() {
    this.branchList = [];
    this.authenticationService.getProductList().pipe(takeUntilDestroyed(this.destroyRef)).subscribe((result) => {
      this.ProductList = result["productList"];
    }, (err) => {
      const errorMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.CHECK_YOUR_INTERNET_CONNECTION");
      this.commonSharedService.showAlert(errorMessage);
    });
    this.form = this.fb.group({
      "email": [null, Validators.compose([Validators.required])],
      "product": [environment.productID, Validators.compose([Validators.required])],
      "password": [null, Validators.compose([Validators.required, Validators.minLength(8)])],
      "captcha": [null, Validators.required]
    });
    this.authenticationService.logout();
  }
  get f() {
    return this.form.controls;
  }
  onSubmit() {
    if (this.form.valid) {
      let branchParam = {
        FirmID: environment.firmID,
        UserID: this.f.email.value,
        ProductID: this.f.product.value
      };
      this.settings.loadingSpinner = true;
      this.authenticationService.getBranchList(branchParam).pipe(takeUntilDestroyed(this.destroyRef)).subscribe((data) => {
        ;
        this.settings.loadingSpinner = false;
        if (data) {
          this.branchList = data["branchID"];
          this.loginNew();
          if (data["branchID"] === -2) {
            this.showAlert(data["status"]["message"], "Alert");
            return;
          }
        } else {
          const errorMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.CHECK_USERNAME_AND_PASSWORD");
          this.commonSharedService.showAlert(errorMessage);
        }
      }, (error) => {
        this.settings.loadingSpinner = false;
      });
    }
  }
  displayMessage(message, type) {
    const dialogRef = this.dialog.open(AlertMessageComponenent, {
      width: "30%",
      data: { message, type }
    });
  }
  loginNew() {
    let postData = {
      employeeID: this.f.email.value,
      password: this.f.password.value,
      formMode: 1,
      branchID: +this.branchList,
      siganture: "115.249.38.210",
      producT_ID: +this.f.product.value,
      forceLogout: 0
    };
    this.authenticationService.login(postData).pipe(first()).subscribe((dataMafil) => {
      this.settings.loadingSpinner = false;
      if (dataMafil["status"]["message"] == "Active session detected. Confirm to terminate previous?") {
        const dialogRef = this.dialog.open(AlertDialogBoxComponent, {
          width: "30%",
          height: "40%",
          data: {
            message: "concurrent",
            datamsg: dataMafil["status"]["message"]
          }
        });
        dialogRef.afterClosed().subscribe((dialogResult) => {
          if (dialogResult.decision == true) {
            this.settings.loadingSpinner = true;
            let postData2 = {
              employeeID: this.f.email.value,
              password: this.f.password.value,
              formMode: 1,
              branchID: +this.branchList,
              siganture: "115.249.38.210",
              producT_ID: +this.f.product.value,
              forceLogout: 1
            };
            this.authenticationService.login(postData2).pipe(first()).subscribe((dataMafil2) => {
              this.settings.loadingSpinner = false;
              if (dataMafil2.loginStatus === 1) {
                const accessToken = dataMafil2.token.access_token;
                const refreshToken = dataMafil2.token.refresh_token;
                localStorage.setItem("accessToken", accessToken);
                localStorage.setItem("refreshToken", refreshToken);
                let currentUser = dataMafil2;
                currentUser.productID = +this.f.product.value;
                currentUser.branchID = this.branchList;
                currentUser["isMafilEmployee"] = 1;
                currentUser.rolefunctionList = dataMafil2["rolefunctionList"];
                localStorage.setItem(environment.localStorageItem, JSON.stringify(currentUser));
                this.settings.loadingSpinner = false;
                this.router.navigate(["/dashboard"]);
                this.secure.setVariable("error", 0);
              } else {
              }
            }, (error) => {
              const alertMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.AN_ERROR_OCCURED");
              this.snackBar.open(alertMessage, "Alert", {
                duration: 3e3,
                panelClass: ["snackbar-error"],
                horizontalPosition: "right",
                verticalPosition: "top"
              });
              this.settings.loadingSpinner = false;
            });
          } else {
          }
        });
      } else if (dataMafil.loginStatus === 1) {
        const accessToken = dataMafil.token.access_token;
        const refreshToken = dataMafil.token.refresh_token;
        localStorage.setItem("accessToken", accessToken);
        localStorage.setItem("refreshToken", refreshToken);
        let currentUser = dataMafil;
        currentUser.productID = +this.f.product.value;
        currentUser.branchID = this.branchList;
        currentUser["isMafilEmployee"] = 1;
        currentUser.rolefunctionList = dataMafil["rolefunctionList"];
        localStorage.setItem(environment.localStorageItem, JSON.stringify(currentUser));
        this.settings.loadingSpinner = false;
        this.router.navigate(["/dashboard"]);
        this.secure.setVariable("error", 0);
      } else {
        this.commonSharedService.showAlert(dataMafil["status"]["message"]);
      }
    }, (error) => {
      this.settings.loadingSpinner = false;
    });
  }
  ssologinNew() {
    let postData = {
      FirmID: environment.firmID,
      Password: this.f.password.value,
      UserID: this.f.email.value,
      ProductID: +this.f.product.value
    };
    this.authenticationService.ssologin(postData).pipe(takeUntilDestroyed(this.destroyRef)).subscribe((ssoData) => {
      if (ssoData.status === "success") {
        const accessToken = ssoData.accessToken.Token.access_token;
        const refreshToken = ssoData.accessToken.Token.refresh_token;
        localStorage.setItem("accessToken", accessToken);
        localStorage.setItem("refreshToken", refreshToken);
        let currentUser = ssoData["accessToken"]["Token"];
        localStorage.setItem(environment.localStorageItem, JSON.stringify(currentUser));
        this.roleList();
      } else {
        this.zone.run(() => {
          this.settings.loadingSpinner = false;
          this.commonSharedService.showAlert(ssoData["status"]["message"]);
        });
      }
    }, (error) => {
      if (error.status === 403) {
        this.zone.run(() => {
          this.settings.loadingSpinner = false;
          const dialogRef = this.dialog.open(AlertDialogBoxComponent, {
            width: "30%",
            height: "32%",
            data: {
              message: "concurrent"
              // datamsg: dataMafil['status']['message'],
            }
          });
          dialogRef.afterClosed().subscribe((dialogResult) => {
            if (dialogResult.decision == true) {
              this.settings.loadingSpinner = true;
              let postData2 = {
                UserName: this.f.email.value
              };
              this.authenticationService.clearSession(postData2).pipe(takeUntilDestroyed(this.destroyRef)).subscribe((data) => {
                const userId = data.message.match(/user:\s*(\d+)/)[1];
                if (userId) {
                  let postDatas = {
                    FirmID: environment.firmID,
                    Password: this.f.password.value,
                    UserID: this.f.email.value,
                    ProductID: +this.f.product.value
                  };
                  this.authenticationService.ssologin(postDatas).pipe(takeUntilDestroyed(this.destroyRef)).subscribe((ssoDatas) => {
                    if (ssoDatas.status === "success") {
                      const accessToken = ssoDatas.accessToken.Token.access_token;
                      const refreshToken = ssoDatas.accessToken.Token.refresh_token;
                      localStorage.setItem("accessToken", accessToken);
                      localStorage.setItem("refreshToken", refreshToken);
                      let currentUser = ssoDatas["accessToken"]["Token"];
                      localStorage.setItem(environment.localStorageItem, JSON.stringify(currentUser));
                      this.roleList();
                      this.settings.loadingSpinner = false;
                    } else {
                      this.zone.run(() => {
                        this.settings.loadingSpinner = false;
                        this.commonSharedService.showAlert(ssoDatas["status"]["message"]);
                      });
                    }
                  }, (error2) => {
                    this.zone.run(() => {
                      this.settings.loadingSpinner = false;
                      const alertMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.INVALID_USER_CREDENTIALS");
                      this.commonSharedService.showAlert(alertMessage);
                      this.form.reset();
                    });
                  });
                } else {
                  const alertMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.INVALID_USER_CREDENTIALS");
                  this.commonSharedService.showAlert(alertMessage);
                  this.form.reset();
                }
              });
            }
          });
        });
      } else {
      }
    });
  }
  roleList() {
    this.authenticationService.roleList().pipe(takeUntilDestroyed(this.destroyRef)).subscribe((logresult) => {
      const logres = JSON.parse(this.shieldService.decrypt(logresult["outputdata"]));
      if (logres["status"].code === 1 && logres["status"].flag === 1) {
        let currentUsers = logres;
        currentUsers.rolefunctionList = logres["rolefunctionList"] != null ? logres["rolefunctionList"] : [];
        localStorage.setItem(environment.localStorageItem, JSON.stringify(currentUsers));
        this.secure.setVariable("error", 0);
        setTimeout(() => {
          this.settings.loadingSpinner = false;
          this.router.navigate(["/dashboard"]);
        }, 100);
      } else {
        setTimeout(() => {
          this.settings.loadingSpinner = false;
          this.commonSharedService.showAlert("Failed to load user roles");
        }, 100);
      }
    }, (error) => {
      setTimeout(() => {
        this.settings.loadingSpinner = false;
        const alertMessage = this.translate.instant("COMMON.MESSAGES.ERRORS.AN_ERROR_OCCURED");
        this.snackBar.open(alertMessage, "Alert", {
          duration: 3e3,
          panelClass: ["snackbar-error"],
          horizontalPosition: "right",
          verticalPosition: "top"
        });
      }, 100);
    });
  }
  showAlert(msg, type) {
    const dialogRef = this.dialog.open(AlertMessageComponenent, {
      width: "30%",
      data: { message: msg, type }
    });
  }
  static {
    this.\u0275fac = function LoginComponent_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _LoginComponent)(\u0275\u0275directiveInject(NgZone), \u0275\u0275directiveInject(MatDialog), \u0275\u0275directiveInject(AppSettings), \u0275\u0275directiveInject(UntypedFormBuilder), \u0275\u0275directiveInject(Router), \u0275\u0275directiveInject(ActivatedRoute), \u0275\u0275directiveInject(DestroyRef), \u0275\u0275directiveInject(CommonService), \u0275\u0275directiveInject(CommonSharedService), \u0275\u0275directiveInject(Sec), \u0275\u0275directiveInject(AuthenticationService), \u0275\u0275directiveInject(AlertService), \u0275\u0275directiveInject(TranslateService), \u0275\u0275directiveInject(ShieldService), \u0275\u0275directiveInject(CustomerService), \u0275\u0275directiveInject(MatSnackBar), \u0275\u0275directiveInject(BrandingService), \u0275\u0275directiveInject(SessionTimeoutService));
    };
  }
  static {
    this.\u0275cmp = /* @__PURE__ */ \u0275\u0275defineComponent({ type: _LoginComponent, selectors: [["app-login"]], viewQuery: function LoginComponent_Query(rf, ctx) {
      if (rf & 1) {
        \u0275\u0275viewQuery(_c0, 7);
      }
      if (rf & 2) {
        let _t;
        \u0275\u0275queryRefresh(_t = \u0275\u0275loadQuery()) && (ctx.canvasRef = _t.first);
      }
    }, decls: 74, vars: 37, consts: [["captchaCanvas", ""], [1, "login-container"], [1, "left-panel"], [1, "brand-section"], [1, "brand-logo", 3, "src"], [1, "brand-title"], [1, "brand-subtitle"], [1, "decorative-element"], [3, "src"], [1, "right-panel"], [1, "login-card"], [1, "card-header"], [1, "logo-container"], [1, "app-logo", 3, "src"], [1, "login-title"], [1, "login-subtitle"], [1, "login-form", 3, "ngSubmit", "formGroup"], [1, "alert-container"], [1, "form-group"], ["appearance", "outline", 1, "form-field"], ["matInput", "", "autocomplete", "off", "formControlName", "email", "maxlength", "10"], ["matPrefix", ""], [4, "ngIf"], ["matInput", "", "autocomplete", "off", "formControlName", "password", "pattern", "(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{8,12}", "maxlength", "12", 3, "type"], ["mat-icon-button", "", "matSuffix", "", "type", "button", 3, "click"], [1, "captcha-container"], [1, "captcha-wrapper"], ["width", "140", "height", "50", 1, "captcha-canvas"], ["mat-icon-button", "", "type", "button", "aria-label", "Refresh CAPTCHA", 1, "captcha-refresh", 3, "click"], ["appearance", "outline", 1, "form-field", "captcha-input"], ["matInput", "", "autocomplete", "off", "formControlName", "captcha", "type", "text", "maxlength", "6"], ["class", "captcha-error", 4, "ngIf"], ["class", "captcha-success", 4, "ngIf"], ["mat-raised-button", "", "type", "submit", 1, "login-button", 3, "disabled"], [1, "forgot-password-container"], [1, "forgot-password-link", 3, "click"], [1, "footer"], [1, "captcha-error"], [1, "hint-icon"], [1, "captcha-success"]], template: function LoginComponent_Template(rf, ctx) {
      if (rf & 1) {
        const _r1 = \u0275\u0275getCurrentView();
        \u0275\u0275elementStart(0, "div", 1)(1, "div", 2)(2, "div", 3);
        \u0275\u0275element(3, "img", 4);
        \u0275\u0275elementStart(4, "h1", 5);
        \u0275\u0275text(5);
        \u0275\u0275pipe(6, "translate");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(7, "h2", 6);
        \u0275\u0275text(8);
        \u0275\u0275pipe(9, "translate");
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(10, "div", 7);
        \u0275\u0275element(11, "img", 8);
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(12, "div", 9)(13, "div", 10)(14, "div", 11)(15, "div", 12);
        \u0275\u0275element(16, "img", 13);
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(17, "h2", 14);
        \u0275\u0275text(18);
        \u0275\u0275pipe(19, "translate");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(20, "p", 15);
        \u0275\u0275text(21);
        \u0275\u0275pipe(22, "translate");
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(23, "form", 16);
        \u0275\u0275listener("ngSubmit", function LoginComponent_Template_form_ngSubmit_23_listener() {
          \u0275\u0275restoreView(_r1);
          return \u0275\u0275resetView(ctx.onSubmit());
        });
        \u0275\u0275elementStart(24, "div", 17);
        \u0275\u0275element(25, "app-alert");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(26, "div", 18)(27, "mat-form-field", 19)(28, "mat-label");
        \u0275\u0275text(29);
        \u0275\u0275pipe(30, "translate");
        \u0275\u0275elementEnd();
        \u0275\u0275element(31, "input", 20);
        \u0275\u0275elementStart(32, "mat-icon", 21);
        \u0275\u0275text(33, "person");
        \u0275\u0275elementEnd();
        \u0275\u0275template(34, LoginComponent_mat_error_34_Template, 3, 3, "mat-error", 22);
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(35, "div", 18)(36, "mat-form-field", 19)(37, "mat-label");
        \u0275\u0275text(38);
        \u0275\u0275pipe(39, "translate");
        \u0275\u0275elementEnd();
        \u0275\u0275element(40, "input", 23);
        \u0275\u0275elementStart(41, "mat-icon", 21);
        \u0275\u0275text(42, "lock");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(43, "button", 24);
        \u0275\u0275listener("click", function LoginComponent_Template_button_click_43_listener() {
          \u0275\u0275restoreView(_r1);
          return \u0275\u0275resetView(ctx.hidePassword = !ctx.hidePassword);
        });
        \u0275\u0275elementStart(44, "mat-icon");
        \u0275\u0275text(45);
        \u0275\u0275elementEnd()();
        \u0275\u0275template(46, LoginComponent_mat_error_46_Template, 3, 3, "mat-error", 22)(47, LoginComponent_mat_error_47_Template, 3, 3, "mat-error", 22);
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(48, "div", 25)(49, "div", 26);
        \u0275\u0275element(50, "canvas", 27, 0);
        \u0275\u0275elementStart(52, "button", 28);
        \u0275\u0275listener("click", function LoginComponent_Template_button_click_52_listener() {
          \u0275\u0275restoreView(_r1);
          return \u0275\u0275resetView(ctx.generateCaptcha());
        });
        \u0275\u0275elementStart(53, "mat-icon");
        \u0275\u0275text(54, "refresh");
        \u0275\u0275elementEnd()()();
        \u0275\u0275elementStart(55, "mat-form-field", 29)(56, "mat-label");
        \u0275\u0275text(57, "Enter CAPTCHA");
        \u0275\u0275elementEnd();
        \u0275\u0275element(58, "input", 30);
        \u0275\u0275elementStart(59, "mat-icon", 21);
        \u0275\u0275text(60, "verified_user");
        \u0275\u0275elementEnd();
        \u0275\u0275template(61, LoginComponent_mat_error_61_Template, 2, 0, "mat-error", 22)(62, LoginComponent_mat_hint_62_Template, 4, 0, "mat-hint", 31)(63, LoginComponent_mat_hint_63_Template, 4, 0, "mat-hint", 32);
        \u0275\u0275elementEnd()();
        \u0275\u0275elementStart(64, "button", 33);
        \u0275\u0275text(65);
        \u0275\u0275pipe(66, "translate");
        \u0275\u0275elementEnd();
        \u0275\u0275elementStart(67, "div", 34)(68, "a", 35);
        \u0275\u0275listener("click", function LoginComponent_Template_a_click_68_listener() {
          \u0275\u0275restoreView(_r1);
          return \u0275\u0275resetView(ctx.openForgotPassword());
        });
        \u0275\u0275text(69);
        \u0275\u0275pipe(70, "translate");
        \u0275\u0275elementEnd()()()();
        \u0275\u0275elementStart(71, "div", 36)(72, "p");
        \u0275\u0275text(73, "\xA9 2025 Manappuram Comptech and Consultants Ltd.");
        \u0275\u0275elementEnd()()()();
      }
      if (rf & 2) {
        let tmp_16_0;
        let tmp_17_0;
        \u0275\u0275advance(3);
        \u0275\u0275property("src", ctx.brandingConfig.brandLogo, \u0275\u0275sanitizeUrl);
        \u0275\u0275advance(2);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(6, 21, "LOGIN.PROJECT.TEXT"));
        \u0275\u0275advance(3);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(9, 23, "LOGIN.PROJECT.TEXT1"));
        \u0275\u0275advance(3);
        \u0275\u0275property("src", ctx.brandingConfig.decorativeImage, \u0275\u0275sanitizeUrl);
        \u0275\u0275advance(5);
        \u0275\u0275property("src", ctx.brandingConfig.logo, \u0275\u0275sanitizeUrl);
        \u0275\u0275advance(2);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(19, 25, "LOGIN.FORM.TITLE"));
        \u0275\u0275advance(3);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(22, 27, "LOGIN.FORM.HEADER"));
        \u0275\u0275advance(2);
        \u0275\u0275property("formGroup", ctx.form);
        \u0275\u0275advance(6);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(30, 29, "LOGIN.FORM.PLACEHOLDER.USER_ID"));
        \u0275\u0275advance(5);
        \u0275\u0275property("ngIf", ctx.form.controls.email.errors == null ? null : ctx.form.controls.email.errors.required);
        \u0275\u0275advance(4);
        \u0275\u0275textInterpolate(\u0275\u0275pipeBind1(39, 31, "LOGIN.FORM.PLACEHOLDER.PASSWORD"));
        \u0275\u0275advance(2);
        \u0275\u0275property("type", ctx.hidePassword ? "password" : "text");
        \u0275\u0275advance(5);
        \u0275\u0275textInterpolate(ctx.hidePassword ? "visibility_off" : "visibility");
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.form.controls.password.errors == null ? null : ctx.form.controls.password.errors.required);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.form.controls.password.errors == null ? null : ctx.form.controls.password.errors.pattern);
        \u0275\u0275advance(14);
        \u0275\u0275property("ngIf", (tmp_16_0 = ctx.form.get("captcha")) == null ? null : tmp_16_0.hasError("required"));
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ((tmp_17_0 = ctx.form.get("captcha")) == null ? null : tmp_17_0.value) && !ctx.captchaValid);
        \u0275\u0275advance();
        \u0275\u0275property("ngIf", ctx.captchaValid);
        \u0275\u0275advance();
        \u0275\u0275property("disabled", !ctx.captchaValid || ctx.form.invalid);
        \u0275\u0275advance();
        \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(66, 33, "LOGIN.FORM.BUTTON.SIGNIN"), " ");
        \u0275\u0275advance(4);
        \u0275\u0275textInterpolate1(" ", \u0275\u0275pipeBind1(70, 35, "LOGIN.FORM.FORGOT_PASSWORD"), " ");
      }
    }, dependencies: [
      CommonModule,
      NgIf,
      FormsModule,
      \u0275NgNoValidate,
      DefaultValueAccessor,
      NgControlStatus,
      NgControlStatusGroup,
      MaxLengthValidator,
      PatternValidator,
      ReactiveFormsModule,
      FormGroupDirective,
      FormControlName,
      TranslateModule,
      SharedModule,
      MatButton,
      MatIconButton,
      MatIcon,
      MatInput,
      MatFormField,
      MatLabel,
      MatHint,
      MatError,
      MatPrefix,
      MatSuffix,
      AlertComponent,
      TranslatePipe
    ], styles: ['\n\n*[_ngcontent-%COMP%] {\n  margin: 0;\n  padding: 0;\n  box-sizing: border-box;\n}\nbody[_ngcontent-%COMP%], \nhtml[_ngcontent-%COMP%] {\n  margin: 0;\n  padding: 0;\n  height: 100%;\n  overflow-x: hidden;\n  font-family: "Roboto", sans-serif;\n}\n.login-container[_ngcontent-%COMP%] {\n  display: flex;\n  height: 100vh;\n  width: 100vw;\n  position: fixed;\n  inset: 0;\n}\n.left-panel[_ngcontent-%COMP%] {\n  width: 60%;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  display: flex;\n  flex-direction: column;\n  justify-content: space-between;\n  padding: 3rem;\n  color: white;\n  position: relative;\n  overflow: hidden;\n}\n.left-panel[_ngcontent-%COMP%]::before {\n  content: "";\n  position: absolute;\n  inset: 0;\n  background:\n    radial-gradient(\n      circle at 20% 80%,\n      rgba(255, 255, 255, 0.1) 0%,\n      transparent 50%);\n}\n.brand-section[_ngcontent-%COMP%] {\n  z-index: 1;\n  margin: -3rem -3rem 0 -3rem;\n  padding: 3rem;\n}\n.brand-section[_ngcontent-%COMP%]   .brand-logo[_ngcontent-%COMP%] {\n  width: 120px;\n  margin-bottom: 2rem;\n  filter: brightness(0) invert(1);\n  margin-top: -50px;\n  max-width: 100%;\n}\n.brand-section[_ngcontent-%COMP%]   .brand-title[_ngcontent-%COMP%] {\n  font-size: 3.5rem;\n  font-weight: 700;\n  margin-bottom: 0.5rem;\n  text-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);\n}\n.brand-section[_ngcontent-%COMP%]   .brand-subtitle[_ngcontent-%COMP%] {\n  font-size: 2.5rem;\n  font-weight: 600;\n  margin-bottom: 1rem;\n  opacity: 0.9;\n  color: white;\n}\n.forgot-password-container[_ngcontent-%COMP%] {\n  text-align: center;\n  margin-bottom: 0.5rem;\n}\n.forgot-password-link[_ngcontent-%COMP%] {\n  color: #667eea;\n  text-decoration: none;\n  font-weight: 700;\n  cursor: pointer;\n  transition: all 0.3s ease;\n  position: relative;\n}\n.forgot-password-link[_ngcontent-%COMP%]:hover {\n  color: #764ba2;\n}\n.forgot-password-link[_ngcontent-%COMP%]::after {\n  content: "";\n  position: absolute;\n  width: 0;\n  height: 2px;\n  bottom: -2px;\n  left: 50%;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  transition: all 0.3s ease;\n  transform: translateX(-50%);\n}\n.forgot-password-link[_ngcontent-%COMP%]:hover::after {\n  width: 100%;\n}\n.decorative-element[_ngcontent-%COMP%] {\n  z-index: 1;\n  margin: 0 -3rem -3rem -3rem;\n  padding: 0 3rem 3rem 3rem;\n  margin-bottom: -105px;\n}\n.decorative-element[_ngcontent-%COMP%]   img[_ngcontent-%COMP%] {\n  width: 200px;\n  opacity: 0.7;\n  filter: brightness(0) invert(1);\n  max-width: 100%;\n}\n.right-panel[_ngcontent-%COMP%] {\n  width: 40%;\n  background:\n    linear-gradient(\n      135deg,\n      #f5f7fa 0%,\n      #c3cfe2 100%);\n  display: flex;\n  flex-direction: column;\n  justify-content: center;\n  align-items: center;\n  padding: 2rem;\n}\n.login-card[_ngcontent-%COMP%] {\n  max-height: 640px;\n  background: white;\n  border-radius: 24px;\n  padding: 2rem;\n  width: 90%;\n  max-width: 400px;\n  margin-bottom: 50px;\n  box-shadow: 0 25px 80px rgba(0, 0, 0, 0.15);\n  animation: _ngcontent-%COMP%_slideUp 0.8s ease-out;\n}\n.card-header[_ngcontent-%COMP%] {\n  text-align: center;\n  margin-bottom: 1.2rem;\n}\n.card-header[_ngcontent-%COMP%]   .logo-container[_ngcontent-%COMP%] {\n  margin-bottom: 0.8rem;\n}\n.card-header[_ngcontent-%COMP%]   .logo-container[_ngcontent-%COMP%]   .app-logo[_ngcontent-%COMP%] {\n  width: 60px;\n  height: 60px;\n  border-radius: 50%;\n  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);\n}\n.card-header[_ngcontent-%COMP%]   .login-title[_ngcontent-%COMP%] {\n  font-size: 1.6rem;\n  font-weight: 600;\n  color: #2d3748;\n  margin-bottom: 0.3rem;\n}\n.card-header[_ngcontent-%COMP%]   .login-subtitle[_ngcontent-%COMP%] {\n  color: #718096;\n  font-size: 0.95rem;\n}\n.login-form[_ngcontent-%COMP%]   .form-group[_ngcontent-%COMP%] {\n  margin-bottom: 10px;\n}\n.login-form[_ngcontent-%COMP%]   .form-field[_ngcontent-%COMP%] {\n  width: 100%;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%] {\n  margin-bottom: 0.5rem;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-wrapper[_ngcontent-%COMP%] {\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  margin-bottom: 1rem;\n  padding: 10px;\n  background:\n    linear-gradient(\n      135deg,\n      #f0f4ff 0%,\n      #e8eeff 100%);\n  border-radius: 12px;\n  border: 2px solid #e2e8f0;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-wrapper[_ngcontent-%COMP%]   .captcha-canvas[_ngcontent-%COMP%] {\n  border-radius: 8px;\n  background: white;\n  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-wrapper[_ngcontent-%COMP%]   .captcha-refresh[_ngcontent-%COMP%] {\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  color: white;\n  width: 40px;\n  height: 40px;\n  border-radius: 10px;\n  transition: all 0.3s ease;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-wrapper[_ngcontent-%COMP%]   .captcha-refresh[_ngcontent-%COMP%]:hover {\n  transform: rotate(180deg);\n  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-wrapper[_ngcontent-%COMP%]   .captcha-refresh[_ngcontent-%COMP%]   mat-icon[_ngcontent-%COMP%] {\n  color: white;\n  font-size: 20px;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-input[_ngcontent-%COMP%] {\n  width: 100%;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-input[_ngcontent-%COMP%]   .captcha-error[_ngcontent-%COMP%] {\n  color: #ef4444;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  font-weight: 500;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-input[_ngcontent-%COMP%]   .captcha-error[_ngcontent-%COMP%]   .hint-icon[_ngcontent-%COMP%] {\n  font-size: 16px;\n  width: 16px;\n  height: 16px;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-input[_ngcontent-%COMP%]   .captcha-success[_ngcontent-%COMP%] {\n  color: #10b981;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  font-weight: 500;\n}\n.login-form[_ngcontent-%COMP%]   .captcha-container[_ngcontent-%COMP%]   .captcha-input[_ngcontent-%COMP%]   .captcha-success[_ngcontent-%COMP%]   .hint-icon[_ngcontent-%COMP%] {\n  font-size: 16px;\n  width: 16px;\n  height: 16px;\n}\n.login-form[_ngcontent-%COMP%]   .login-button[_ngcontent-%COMP%] {\n  width: 100%;\n  height: 50px;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  color: white;\n  border-radius: 12px;\n  font-size: 1rem;\n  font-weight: 600;\n  margin: 0.3rem 0 0.5rem 0;\n  text-transform: none;\n  box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);\n  transition: all 0.3s ease;\n}\n.login-form[_ngcontent-%COMP%]   .login-button[_ngcontent-%COMP%]:hover:not(:disabled) {\n  transform: translateY(-2px);\n  box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);\n}\n.login-form[_ngcontent-%COMP%]   .login-button[_ngcontent-%COMP%]:disabled {\n  opacity: 0.6;\n  cursor: not-allowed;\n}\n.footer[_ngcontent-%COMP%] {\n  position: relative;\n  bottom: 2rem;\n  left: 50%;\n  transform: translateX(-50%);\n  color: #718096;\n  font-size: 0.875rem;\n  text-align: center;\n  white-space: nowrap;\n}\n@media (max-width: 768px) {\n  .login-container[_ngcontent-%COMP%] {\n    flex-direction: column;\n    height: auto;\n    overflow-y: auto;\n  }\n  .left-panel[_ngcontent-%COMP%], \n   .right-panel[_ngcontent-%COMP%] {\n    width: 100%;\n    padding: 2rem;\n  }\n  .brand-title[_ngcontent-%COMP%] {\n    font-size: 2.5rem;\n  }\n  .brand-subtitle[_ngcontent-%COMP%] {\n    font-size: 1.8rem;\n  }\n  .decorative-element[_ngcontent-%COMP%] {\n    display: none;\n  }\n  .login-card[_ngcontent-%COMP%] {\n    margin-top: 1rem;\n    max-width: 100%;\n  }\n  .footer[_ngcontent-%COMP%] {\n    position: static;\n    transform: none;\n    margin-top: 1rem;\n    white-space: normal;\n  }\n}\n@media (max-width: 480px) {\n  .brand-title[_ngcontent-%COMP%] {\n    font-size: 1.8rem;\n  }\n  .brand-subtitle[_ngcontent-%COMP%] {\n    font-size: 1.2rem;\n  }\n  .login-card[_ngcontent-%COMP%] {\n    padding: 1.5rem;\n    margin: 1rem 0;\n  }\n  .login-title[_ngcontent-%COMP%] {\n    font-size: 1.2rem;\n  }\n  .login-subtitle[_ngcontent-%COMP%] {\n    font-size: 0.85rem;\n  }\n  .footer[_ngcontent-%COMP%] {\n    font-size: 0.75rem;\n  }\n}\n@keyframes _ngcontent-%COMP%_slideUp {\n  from {\n    opacity: 0;\n    transform: translateY(30px);\n  }\n  to {\n    opacity: 1;\n    transform: translateY(0);\n  }\n}', "\n\n@-webkit-keyframes _ngcontent-%COMP%_bounce {\n  0%, 20%, 53%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  40%, 43% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -30px, 0);\n    transform: translate3d(0, -30px, 0);\n  }\n  70% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -15px, 0);\n    transform: translate3d(0, -15px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -4px, 0);\n    transform: translate3d(0, -4px, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounce {\n  0%, 20%, 53%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  40%, 43% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -30px, 0);\n    transform: translate3d(0, -30px, 0);\n  }\n  70% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -15px, 0);\n    transform: translate3d(0, -15px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -4px, 0);\n    transform: translate3d(0, -4px, 0);\n  }\n}\n.bounce[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounce;\n  animation-name: _ngcontent-%COMP%_bounce;\n  -webkit-transform-origin: center bottom;\n  transform-origin: center bottom;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flash {\n  0%, 50%, to {\n    opacity: 1;\n  }\n  25%, 75% {\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_flash {\n  0%, 50%, to {\n    opacity: 1;\n  }\n  25%, 75% {\n    opacity: 0;\n  }\n}\n.flash[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_flash;\n  animation-name: _ngcontent-%COMP%_flash;\n}\n@-webkit-keyframes _ngcontent-%COMP%_pulse {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.05, 1.05, 1.05);\n    transform: scale3d(1.05, 1.05, 1.05);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_pulse {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.05, 1.05, 1.05);\n    transform: scale3d(1.05, 1.05, 1.05);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.pulse[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_pulse;\n  animation-name: _ngcontent-%COMP%_pulse;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rubberBand {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  30% {\n    -webkit-transform: scale3d(1.25, 0.75, 1);\n    transform: scale3d(1.25, 0.75, 1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.75, 1.25, 1);\n    transform: scale3d(0.75, 1.25, 1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.15, 0.85, 1);\n    transform: scale3d(1.15, 0.85, 1);\n  }\n  65% {\n    -webkit-transform: scale3d(0.95, 1.05, 1);\n    transform: scale3d(0.95, 1.05, 1);\n  }\n  75% {\n    -webkit-transform: scale3d(1.05, 0.95, 1);\n    transform: scale3d(1.05, 0.95, 1);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_rubberBand {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  30% {\n    -webkit-transform: scale3d(1.25, 0.75, 1);\n    transform: scale3d(1.25, 0.75, 1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.75, 1.25, 1);\n    transform: scale3d(0.75, 1.25, 1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.15, 0.85, 1);\n    transform: scale3d(1.15, 0.85, 1);\n  }\n  65% {\n    -webkit-transform: scale3d(0.95, 1.05, 1);\n    transform: scale3d(0.95, 1.05, 1);\n  }\n  75% {\n    -webkit-transform: scale3d(1.05, 0.95, 1);\n    transform: scale3d(1.05, 0.95, 1);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.rubberBand[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rubberBand;\n  animation-name: _ngcontent-%COMP%_rubberBand;\n}\n@-webkit-keyframes _ngcontent-%COMP%_shake {\n  0%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  10%, 30%, 50%, 70%, 90% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  20%, 40%, 60%, 80% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_shake {\n  0%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  10%, 30%, 50%, 70%, 90% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  20%, 40%, 60%, 80% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n}\n.shake[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_shake;\n  animation-name: _ngcontent-%COMP%_shake;\n}\n@-webkit-keyframes _ngcontent-%COMP%_headShake {\n  0% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n  6.5% {\n    -webkit-transform: translateX(-6px) rotateY(-9deg);\n    transform: translateX(-6px) rotateY(-9deg);\n  }\n  18.5% {\n    -webkit-transform: translateX(5px) rotateY(7deg);\n    transform: translateX(5px) rotateY(7deg);\n  }\n  31.5% {\n    -webkit-transform: translateX(-3px) rotateY(-5deg);\n    transform: translateX(-3px) rotateY(-5deg);\n  }\n  43.5% {\n    -webkit-transform: translateX(2px) rotateY(3deg);\n    transform: translateX(2px) rotateY(3deg);\n  }\n  50% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_headShake {\n  0% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n  6.5% {\n    -webkit-transform: translateX(-6px) rotateY(-9deg);\n    transform: translateX(-6px) rotateY(-9deg);\n  }\n  18.5% {\n    -webkit-transform: translateX(5px) rotateY(7deg);\n    transform: translateX(5px) rotateY(7deg);\n  }\n  31.5% {\n    -webkit-transform: translateX(-3px) rotateY(-5deg);\n    transform: translateX(-3px) rotateY(-5deg);\n  }\n  43.5% {\n    -webkit-transform: translateX(2px) rotateY(3deg);\n    transform: translateX(2px) rotateY(3deg);\n  }\n  50% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n}\n.headShake[_ngcontent-%COMP%] {\n  -webkit-animation-timing-function: ease-in-out;\n  animation-timing-function: ease-in-out;\n  -webkit-animation-name: _ngcontent-%COMP%_headShake;\n  animation-name: _ngcontent-%COMP%_headShake;\n}\n@-webkit-keyframes _ngcontent-%COMP%_swing {\n  20% {\n    -webkit-transform: rotate(15deg);\n    transform: rotate(15deg);\n  }\n  40% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  60% {\n    -webkit-transform: rotate(5deg);\n    transform: rotate(5deg);\n  }\n  80% {\n    -webkit-transform: rotate(-5deg);\n    transform: rotate(-5deg);\n  }\n  to {\n    -webkit-transform: rotate(0deg);\n    transform: rotate(0deg);\n  }\n}\n@keyframes _ngcontent-%COMP%_swing {\n  20% {\n    -webkit-transform: rotate(15deg);\n    transform: rotate(15deg);\n  }\n  40% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  60% {\n    -webkit-transform: rotate(5deg);\n    transform: rotate(5deg);\n  }\n  80% {\n    -webkit-transform: rotate(-5deg);\n    transform: rotate(-5deg);\n  }\n  to {\n    -webkit-transform: rotate(0deg);\n    transform: rotate(0deg);\n  }\n}\n.swing[_ngcontent-%COMP%] {\n  -webkit-transform-origin: top center;\n  transform-origin: top center;\n  -webkit-animation-name: _ngcontent-%COMP%_swing;\n  animation-name: _ngcontent-%COMP%_swing;\n}\n@-webkit-keyframes _ngcontent-%COMP%_tada {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  10%, 20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n    transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n  }\n  30%, 50%, 70%, 90% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n  }\n  40%, 60%, 80% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_tada {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  10%, 20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n    transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n  }\n  30%, 50%, 70%, 90% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n  }\n  40%, 60%, 80% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.tada[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_tada;\n  animation-name: _ngcontent-%COMP%_tada;\n}\n@-webkit-keyframes _ngcontent-%COMP%_wobble {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  15% {\n    -webkit-transform: translate3d(-25%, 0, 0) rotate(-5deg);\n    transform: translate3d(-25%, 0, 0) rotate(-5deg);\n  }\n  30% {\n    -webkit-transform: translate3d(20%, 0, 0) rotate(3deg);\n    transform: translate3d(20%, 0, 0) rotate(3deg);\n  }\n  45% {\n    -webkit-transform: translate3d(-15%, 0, 0) rotate(-3deg);\n    transform: translate3d(-15%, 0, 0) rotate(-3deg);\n  }\n  60% {\n    -webkit-transform: translate3d(10%, 0, 0) rotate(2deg);\n    transform: translate3d(10%, 0, 0) rotate(2deg);\n  }\n  75% {\n    -webkit-transform: translate3d(-5%, 0, 0) rotate(-1deg);\n    transform: translate3d(-5%, 0, 0) rotate(-1deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_wobble {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  15% {\n    -webkit-transform: translate3d(-25%, 0, 0) rotate(-5deg);\n    transform: translate3d(-25%, 0, 0) rotate(-5deg);\n  }\n  30% {\n    -webkit-transform: translate3d(20%, 0, 0) rotate(3deg);\n    transform: translate3d(20%, 0, 0) rotate(3deg);\n  }\n  45% {\n    -webkit-transform: translate3d(-15%, 0, 0) rotate(-3deg);\n    transform: translate3d(-15%, 0, 0) rotate(-3deg);\n  }\n  60% {\n    -webkit-transform: translate3d(10%, 0, 0) rotate(2deg);\n    transform: translate3d(10%, 0, 0) rotate(2deg);\n  }\n  75% {\n    -webkit-transform: translate3d(-5%, 0, 0) rotate(-1deg);\n    transform: translate3d(-5%, 0, 0) rotate(-1deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.wobble[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_wobble;\n  animation-name: _ngcontent-%COMP%_wobble;\n}\n@-webkit-keyframes _ngcontent-%COMP%_jello {\n  0%, 11.1%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  22.2% {\n    -webkit-transform: skewX(-12.5deg) skewY(-12.5deg);\n    transform: skewX(-12.5deg) skewY(-12.5deg);\n  }\n  33.3% {\n    -webkit-transform: skewX(6.25deg) skewY(6.25deg);\n    transform: skewX(6.25deg) skewY(6.25deg);\n  }\n  44.4% {\n    -webkit-transform: skewX(-3.125deg) skewY(-3.125deg);\n    transform: skewX(-3.125deg) skewY(-3.125deg);\n  }\n  55.5% {\n    -webkit-transform: skewX(1.5625deg) skewY(1.5625deg);\n    transform: skewX(1.5625deg) skewY(1.5625deg);\n  }\n  66.6% {\n    -webkit-transform: skewX(-0.78125deg) skewY(-0.78125deg);\n    transform: skewX(-0.78125deg) skewY(-0.78125deg);\n  }\n  77.7% {\n    -webkit-transform: skewX(0.390625deg) skewY(0.390625deg);\n    transform: skewX(0.390625deg) skewY(0.390625deg);\n  }\n  88.8% {\n    -webkit-transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n    transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n  }\n}\n@keyframes _ngcontent-%COMP%_jello {\n  0%, 11.1%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  22.2% {\n    -webkit-transform: skewX(-12.5deg) skewY(-12.5deg);\n    transform: skewX(-12.5deg) skewY(-12.5deg);\n  }\n  33.3% {\n    -webkit-transform: skewX(6.25deg) skewY(6.25deg);\n    transform: skewX(6.25deg) skewY(6.25deg);\n  }\n  44.4% {\n    -webkit-transform: skewX(-3.125deg) skewY(-3.125deg);\n    transform: skewX(-3.125deg) skewY(-3.125deg);\n  }\n  55.5% {\n    -webkit-transform: skewX(1.5625deg) skewY(1.5625deg);\n    transform: skewX(1.5625deg) skewY(1.5625deg);\n  }\n  66.6% {\n    -webkit-transform: skewX(-0.78125deg) skewY(-0.78125deg);\n    transform: skewX(-0.78125deg) skewY(-0.78125deg);\n  }\n  77.7% {\n    -webkit-transform: skewX(0.390625deg) skewY(0.390625deg);\n    transform: skewX(0.390625deg) skewY(0.390625deg);\n  }\n  88.8% {\n    -webkit-transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n    transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n  }\n}\n.jello[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_jello;\n  animation-name: _ngcontent-%COMP%_jello;\n  -webkit-transform-origin: center;\n  transform-origin: center;\n}\n@-webkit-keyframes _ngcontent-%COMP%_heartBeat {\n  0% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  14% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  28% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  42% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  70% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_heartBeat {\n  0% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  14% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  28% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  42% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  70% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n.heartBeat[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_heartBeat;\n  animation-name: _ngcontent-%COMP%_heartBeat;\n  -webkit-animation-duration: 1.3s;\n  animation-duration: 1.3s;\n  -webkit-animation-timing-function: ease-in-out;\n  animation-timing-function: ease-in-out;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceIn {\n  0%, 20%, 40%, 60%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  20% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.03, 1.03, 1.03);\n    transform: scale3d(1.03, 1.03, 1.03);\n  }\n  80% {\n    -webkit-transform: scale3d(0.97, 0.97, 0.97);\n    transform: scale3d(0.97, 0.97, 0.97);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceIn {\n  0%, 20%, 40%, 60%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  20% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.03, 1.03, 1.03);\n    transform: scale3d(1.03, 1.03, 1.03);\n  }\n  80% {\n    -webkit-transform: scale3d(0.97, 0.97, 0.97);\n    transform: scale3d(0.97, 0.97, 0.97);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.bounceIn[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: _ngcontent-%COMP%_bounceIn;\n  animation-name: _ngcontent-%COMP%_bounceIn;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceInDown {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -3000px, 0);\n    transform: translate3d(0, -3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 25px, 0);\n    transform: translate3d(0, 25px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, 5px, 0);\n    transform: translate3d(0, 5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceInDown {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -3000px, 0);\n    transform: translate3d(0, -3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 25px, 0);\n    transform: translate3d(0, 25px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, 5px, 0);\n    transform: translate3d(0, 5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceInDown;\n  animation-name: _ngcontent-%COMP%_bounceInDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceInLeft {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-3000px, 0, 0);\n    transform: translate3d(-3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(25px, 0, 0);\n    transform: translate3d(25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(5px, 0, 0);\n    transform: translate3d(5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceInLeft {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-3000px, 0, 0);\n    transform: translate3d(-3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(25px, 0, 0);\n    transform: translate3d(25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(5px, 0, 0);\n    transform: translate3d(5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceInLeft;\n  animation-name: _ngcontent-%COMP%_bounceInLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceInRight {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(3000px, 0, 0);\n    transform: translate3d(3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(-25px, 0, 0);\n    transform: translate3d(-25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(-5px, 0, 0);\n    transform: translate3d(-5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceInRight {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(3000px, 0, 0);\n    transform: translate3d(3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(-25px, 0, 0);\n    transform: translate3d(-25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(-5px, 0, 0);\n    transform: translate3d(-5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceInRight;\n  animation-name: _ngcontent-%COMP%_bounceInRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceInUp {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 3000px, 0);\n    transform: translate3d(0, 3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -5px, 0);\n    transform: translate3d(0, -5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceInUp {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 3000px, 0);\n    transform: translate3d(0, 3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -5px, 0);\n    transform: translate3d(0, -5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceInUp;\n  animation-name: _ngcontent-%COMP%_bounceInUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceOut {\n  20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  50%, 55% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceOut {\n  20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  50%, 55% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n}\n.bounceOut[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: _ngcontent-%COMP%_bounceOut;\n  animation-name: _ngcontent-%COMP%_bounceOut;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceOutDown {\n  20% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceOutDown {\n  20% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n.bounceOutDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceOutDown;\n  animation-name: _ngcontent-%COMP%_bounceOutDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceOutLeft {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(20px, 0, 0);\n    transform: translate3d(20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceOutLeft {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(20px, 0, 0);\n    transform: translate3d(20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n.bounceOutLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceOutLeft;\n  animation-name: _ngcontent-%COMP%_bounceOutLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceOutRight {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(-20px, 0, 0);\n    transform: translate3d(-20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceOutRight {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(-20px, 0, 0);\n    transform: translate3d(-20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n.bounceOutRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceOutRight;\n  animation-name: _ngcontent-%COMP%_bounceOutRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_bounceOutUp {\n  20% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 20px, 0);\n    transform: translate3d(0, 20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_bounceOutUp {\n  20% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 20px, 0);\n    transform: translate3d(0, 20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n.bounceOutUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_bounceOutUp;\n  animation-name: _ngcontent-%COMP%_bounceOutUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeIn {\n  0% {\n    opacity: 0;\n  }\n  to {\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeIn {\n  0% {\n    opacity: 0;\n  }\n  to {\n    opacity: 1;\n  }\n}\n.fadeIn[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeIn;\n  animation-name: _ngcontent-%COMP%_fadeIn;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInDown;\n  animation-name: _ngcontent-%COMP%_fadeInDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInDownBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInDownBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInDownBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInDownBig;\n  animation-name: _ngcontent-%COMP%_fadeInDownBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInLeft;\n  animation-name: _ngcontent-%COMP%_fadeInLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInLeftBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInLeftBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInLeftBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInLeftBig;\n  animation-name: _ngcontent-%COMP%_fadeInLeftBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInRight;\n  animation-name: _ngcontent-%COMP%_fadeInRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInRightBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInRightBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInRightBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInRightBig;\n  animation-name: _ngcontent-%COMP%_fadeInRightBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInUp;\n  animation-name: _ngcontent-%COMP%_fadeInUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeInUpBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeInUpBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInUpBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeInUpBig;\n  animation-name: _ngcontent-%COMP%_fadeInUpBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n  }\n}\n.fadeOut[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOut;\n  animation-name: _ngcontent-%COMP%_fadeOut;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutDown {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutDown {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n.fadeOutDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutDown;\n  animation-name: _ngcontent-%COMP%_fadeOutDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutDownBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutDownBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n.fadeOutDownBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutDownBig;\n  animation-name: _ngcontent-%COMP%_fadeOutDownBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutLeft {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutLeft {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n.fadeOutLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutLeft;\n  animation-name: _ngcontent-%COMP%_fadeOutLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutLeftBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutLeftBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n.fadeOutLeftBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutLeftBig;\n  animation-name: _ngcontent-%COMP%_fadeOutLeftBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutRight {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutRight {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n.fadeOutRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutRight;\n  animation-name: _ngcontent-%COMP%_fadeOutRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutRightBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutRightBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n.fadeOutRightBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutRightBig;\n  animation-name: _ngcontent-%COMP%_fadeOutRightBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutUp {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutUp {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n.fadeOutUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutUp;\n  animation-name: _ngcontent-%COMP%_fadeOutUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_fadeOutUpBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_fadeOutUpBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n.fadeOutUpBig[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_fadeOutUpBig;\n  animation-name: _ngcontent-%COMP%_fadeOutUpBig;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flip {\n  0% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  40% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  50% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  80% {\n    -webkit-transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  to {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n}\n@keyframes _ngcontent-%COMP%_flip {\n  0% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  40% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  50% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  80% {\n    -webkit-transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  to {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n}\n.animated.flip[_ngcontent-%COMP%] {\n  -webkit-backface-visibility: visible;\n  backface-visibility: visible;\n  -webkit-animation-name: _ngcontent-%COMP%_flip;\n  animation-name: _ngcontent-%COMP%_flip;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flipInX {\n  0% {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateX(10deg);\n    transform: perspective(400px) rotateX(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateX(-5deg);\n    transform: perspective(400px) rotateX(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n@keyframes _ngcontent-%COMP%_flipInX {\n  0% {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateX(10deg);\n    transform: perspective(400px) rotateX(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateX(-5deg);\n    transform: perspective(400px) rotateX(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n.flipInX[_ngcontent-%COMP%] {\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: _ngcontent-%COMP%_flipInX;\n  animation-name: _ngcontent-%COMP%_flipInX;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flipInY {\n  0% {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateY(-20deg);\n    transform: perspective(400px) rotateY(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateY(10deg);\n    transform: perspective(400px) rotateY(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateY(-5deg);\n    transform: perspective(400px) rotateY(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n@keyframes _ngcontent-%COMP%_flipInY {\n  0% {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateY(-20deg);\n    transform: perspective(400px) rotateY(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateY(10deg);\n    transform: perspective(400px) rotateY(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateY(-5deg);\n    transform: perspective(400px) rotateY(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n.flipInY[_ngcontent-%COMP%] {\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: _ngcontent-%COMP%_flipInY;\n  animation-name: _ngcontent-%COMP%_flipInY;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flipOutX {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_flipOutX {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    opacity: 0;\n  }\n}\n.flipOutX[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: _ngcontent-%COMP%_flipOutX;\n  animation-name: _ngcontent-%COMP%_flipOutX;\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n}\n@-webkit-keyframes _ngcontent-%COMP%_flipOutY {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateY(-15deg);\n    transform: perspective(400px) rotateY(-15deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_flipOutY {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateY(-15deg);\n    transform: perspective(400px) rotateY(-15deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    opacity: 0;\n  }\n}\n.flipOutY[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: _ngcontent-%COMP%_flipOutY;\n  animation-name: _ngcontent-%COMP%_flipOutY;\n}\n@-webkit-keyframes _ngcontent-%COMP%_lightSpeedIn {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(-30deg);\n    transform: translate3d(100%, 0, 0) skewX(-30deg);\n    opacity: 0;\n  }\n  60% {\n    -webkit-transform: skewX(20deg);\n    transform: skewX(20deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: skewX(-5deg);\n    transform: skewX(-5deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_lightSpeedIn {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(-30deg);\n    transform: translate3d(100%, 0, 0) skewX(-30deg);\n    opacity: 0;\n  }\n  60% {\n    -webkit-transform: skewX(20deg);\n    transform: skewX(20deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: skewX(-5deg);\n    transform: skewX(-5deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.lightSpeedIn[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_lightSpeedIn;\n  animation-name: _ngcontent-%COMP%_lightSpeedIn;\n  -webkit-animation-timing-function: ease-out;\n  animation-timing-function: ease-out;\n}\n@-webkit-keyframes _ngcontent-%COMP%_lightSpeedOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(30deg);\n    transform: translate3d(100%, 0, 0) skewX(30deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_lightSpeedOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(30deg);\n    transform: translate3d(100%, 0, 0) skewX(30deg);\n    opacity: 0;\n  }\n}\n.lightSpeedOut[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_lightSpeedOut;\n  animation-name: _ngcontent-%COMP%_lightSpeedOut;\n  -webkit-animation-timing-function: ease-in;\n  animation-timing-function: ease-in;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateIn {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(-200deg);\n    transform: rotate(-200deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateIn {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(-200deg);\n    transform: rotate(-200deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateIn[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateIn;\n  animation-name: _ngcontent-%COMP%_rotateIn;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateInDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateInDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInDownLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateInDownLeft;\n  animation-name: _ngcontent-%COMP%_rotateInDownLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateInDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateInDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInDownRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateInDownRight;\n  animation-name: _ngcontent-%COMP%_rotateInDownRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateInUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateInUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInUpLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateInUpLeft;\n  animation-name: _ngcontent-%COMP%_rotateInUpLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateInUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-90deg);\n    transform: rotate(-90deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateInUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-90deg);\n    transform: rotate(-90deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInUpRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateInUpRight;\n  animation-name: _ngcontent-%COMP%_rotateInUpRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateOut {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(200deg);\n    transform: rotate(200deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateOut {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(200deg);\n    transform: rotate(200deg);\n    opacity: 0;\n  }\n}\n.rotateOut[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateOut;\n  animation-name: _ngcontent-%COMP%_rotateOut;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateOutDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateOutDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n}\n.rotateOutDownLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateOutDownLeft;\n  animation-name: _ngcontent-%COMP%_rotateOutDownLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateOutDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateOutDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n.rotateOutDownRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateOutDownRight;\n  animation-name: _ngcontent-%COMP%_rotateOutDownRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateOutUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateOutUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n.rotateOutUpLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateOutUpLeft;\n  animation-name: _ngcontent-%COMP%_rotateOutUpLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rotateOutUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(90deg);\n    transform: rotate(90deg);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_rotateOutUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(90deg);\n    transform: rotate(90deg);\n    opacity: 0;\n  }\n}\n.rotateOutUpRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rotateOutUpRight;\n  animation-name: _ngcontent-%COMP%_rotateOutUpRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_hinge {\n  0% {\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  20%, 60% {\n    -webkit-transform: rotate(80deg);\n    transform: rotate(80deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  40%, 80% {\n    -webkit-transform: rotate(60deg);\n    transform: rotate(60deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(0, 700px, 0);\n    transform: translate3d(0, 700px, 0);\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_hinge {\n  0% {\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  20%, 60% {\n    -webkit-transform: rotate(80deg);\n    transform: rotate(80deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  40%, 80% {\n    -webkit-transform: rotate(60deg);\n    transform: rotate(60deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(0, 700px, 0);\n    transform: translate3d(0, 700px, 0);\n    opacity: 0;\n  }\n}\n.hinge[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 2s;\n  animation-duration: 2s;\n  -webkit-animation-name: _ngcontent-%COMP%_hinge;\n  animation-name: _ngcontent-%COMP%_hinge;\n}\n@-webkit-keyframes _ngcontent-%COMP%_jackInTheBox {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale(0.1) rotate(30deg);\n    transform: scale(0.1) rotate(30deg);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n  }\n  50% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  70% {\n    -webkit-transform: rotate(3deg);\n    transform: rotate(3deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n@keyframes _ngcontent-%COMP%_jackInTheBox {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale(0.1) rotate(30deg);\n    transform: scale(0.1) rotate(30deg);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n  }\n  50% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  70% {\n    -webkit-transform: rotate(3deg);\n    transform: rotate(3deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n.jackInTheBox[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_jackInTheBox;\n  animation-name: _ngcontent-%COMP%_jackInTheBox;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rollIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0) rotate(-120deg);\n    transform: translate3d(-100%, 0, 0) rotate(-120deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_rollIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0) rotate(-120deg);\n    transform: translate3d(-100%, 0, 0) rotate(-120deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.rollIn[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rollIn;\n  animation-name: _ngcontent-%COMP%_rollIn;\n}\n@-webkit-keyframes _ngcontent-%COMP%_rollOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0) rotate(120deg);\n    transform: translate3d(100%, 0, 0) rotate(120deg);\n  }\n}\n@keyframes _ngcontent-%COMP%_rollOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0) rotate(120deg);\n    transform: translate3d(100%, 0, 0) rotate(120deg);\n  }\n}\n.rollOut[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_rollOut;\n  animation-name: _ngcontent-%COMP%_rollOut;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  50% {\n    opacity: 1;\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  50% {\n    opacity: 1;\n  }\n}\n.zoomIn[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomIn;\n  animation-name: _ngcontent-%COMP%_zoomIn;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomInDown;\n  animation-name: _ngcontent-%COMP%_zoomInDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomInLeft;\n  animation-name: _ngcontent-%COMP%_zoomInLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomInRight;\n  animation-name: _ngcontent-%COMP%_zoomInRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomInUp;\n  animation-name: _ngcontent-%COMP%_zoomInUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomOut {\n  0% {\n    opacity: 1;\n  }\n  50% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  to {\n    opacity: 0;\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomOut {\n  0% {\n    opacity: 1;\n  }\n  50% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  to {\n    opacity: 0;\n  }\n}\n.zoomOut[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomOut;\n  animation-name: _ngcontent-%COMP%_zoomOut;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomOutDown {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomOutDown {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomOutDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomOutDown;\n  animation-name: _ngcontent-%COMP%_zoomOutDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomOutLeft {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(-2000px, 0, 0);\n    transform: scale(0.1) translate3d(-2000px, 0, 0);\n    -webkit-transform-origin: left center;\n    transform-origin: left center;\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomOutLeft {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(-2000px, 0, 0);\n    transform: scale(0.1) translate3d(-2000px, 0, 0);\n    -webkit-transform-origin: left center;\n    transform-origin: left center;\n  }\n}\n.zoomOutLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomOutLeft;\n  animation-name: _ngcontent-%COMP%_zoomOutLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomOutRight {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(2000px, 0, 0);\n    transform: scale(0.1) translate3d(2000px, 0, 0);\n    -webkit-transform-origin: right center;\n    transform-origin: right center;\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomOutRight {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(2000px, 0, 0);\n    transform: scale(0.1) translate3d(2000px, 0, 0);\n    -webkit-transform-origin: right center;\n    transform-origin: right center;\n  }\n}\n.zoomOutRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomOutRight;\n  animation-name: _ngcontent-%COMP%_zoomOutRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_zoomOutUp {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes _ngcontent-%COMP%_zoomOutUp {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomOutUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_zoomOutUp;\n  animation-name: _ngcontent-%COMP%_zoomOutUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideInDown {\n  0% {\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideInDown {\n  0% {\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideInDown;\n  animation-name: _ngcontent-%COMP%_slideInDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideInLeft {\n  0% {\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideInLeft {\n  0% {\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideInLeft;\n  animation-name: _ngcontent-%COMP%_slideInLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideInRight {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideInRight {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideInRight;\n  animation-name: _ngcontent-%COMP%_slideInRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideInUp {\n  0% {\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideInUp {\n  0% {\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideInUp;\n  animation-name: _ngcontent-%COMP%_slideInUp;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideOutDown {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideOutDown {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n.slideOutDown[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideOutDown;\n  animation-name: _ngcontent-%COMP%_slideOutDown;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideOutLeft {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideOutLeft {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n.slideOutLeft[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideOutLeft;\n  animation-name: _ngcontent-%COMP%_slideOutLeft;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideOutRight {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideOutRight {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n.slideOutRight[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideOutRight;\n  animation-name: _ngcontent-%COMP%_slideOutRight;\n}\n@-webkit-keyframes _ngcontent-%COMP%_slideOutUp {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n@keyframes _ngcontent-%COMP%_slideOutUp {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n.slideOutUp[_ngcontent-%COMP%] {\n  -webkit-animation-name: _ngcontent-%COMP%_slideOutUp;\n  animation-name: _ngcontent-%COMP%_slideOutUp;\n}\n.animated[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 1s;\n  animation-duration: 1s;\n  -webkit-animation-fill-mode: both;\n  animation-fill-mode: both;\n}\n.animated.infinite[_ngcontent-%COMP%] {\n  -webkit-animation-iteration-count: infinite;\n  animation-iteration-count: infinite;\n}\n.animated.delay-1s[_ngcontent-%COMP%] {\n  -webkit-animation-delay: 1s;\n  animation-delay: 1s;\n}\n.animated.delay-2s[_ngcontent-%COMP%] {\n  -webkit-animation-delay: 2s;\n  animation-delay: 2s;\n}\n.animated.delay-3s[_ngcontent-%COMP%] {\n  -webkit-animation-delay: 3s;\n  animation-delay: 3s;\n}\n.animated.delay-4s[_ngcontent-%COMP%] {\n  -webkit-animation-delay: 4s;\n  animation-delay: 4s;\n}\n.animated.delay-5s[_ngcontent-%COMP%] {\n  -webkit-animation-delay: 5s;\n  animation-delay: 5s;\n}\n.animated.fast[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.8s;\n  animation-duration: 0.8s;\n}\n.animated.faster[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 0.5s;\n  animation-duration: 0.5s;\n}\n.animated.slow[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 2s;\n  animation-duration: 2s;\n}\n.animated.slower[_ngcontent-%COMP%] {\n  -webkit-animation-duration: 3s;\n  animation-duration: 3s;\n}\n@media (prefers-reduced-motion: reduce), (print) {\n  .animated[_ngcontent-%COMP%] {\n    -webkit-animation-duration: 1ms !important;\n    animation-duration: 1ms !important;\n    -webkit-transition-duration: 1ms !important;\n    transition-duration: 1ms !important;\n    -webkit-animation-iteration-count: 1 !important;\n    animation-iteration-count: 1 !important;\n  }\n}\n\n\n\n\n\n\n\n"] });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(LoginComponent, [{
    type: Component,
    args: [{ selector: "app-login", imports: [
      CommonModule,
      FormsModule,
      ReactiveFormsModule,
      TranslateModule,
      SharedModule
    ], template: `<div class="login-container">\r
  <div class="left-panel">\r
    <div class="brand-section">\r
      <img [src]="brandingConfig.brandLogo" class="brand-logo">\r
      <h1 class="brand-title">{{ 'LOGIN.PROJECT.TEXT' | translate }}</h1>\r
      <h2 class="brand-subtitle">{{ 'LOGIN.PROJECT.TEXT1' | translate }}</h2>\r
      <!-- <p class="brand-description">Streamlined loan origination for MSME businesses</p> -->\r
    </div>\r
    <div class="decorative-element">\r
      <img [src]="brandingConfig.decorativeImage">\r
    </div>\r
  </div>\r
  \r
  <div class="right-panel">\r
    <div class="login-card">\r
      <div class="card-header">\r
        <div class="logo-container">\r
          <img [src]="brandingConfig.logo" class="app-logo">\r
        </div>\r
        <h2 class="login-title">{{ 'LOGIN.FORM.TITLE' | translate }}</h2>\r
        <p class="login-subtitle">{{ 'LOGIN.FORM.HEADER' | translate }}</p>\r
      </div>\r
      \r
      <form class="login-form" [formGroup]="form" (ngSubmit)="onSubmit()">\r
        <div class="alert-container">\r
          <app-alert></app-alert>\r
        </div>\r
        \r
        <div class="form-group">\r
          <mat-form-field class="form-field" appearance="outline">\r
            <mat-label>{{ 'LOGIN.FORM.PLACEHOLDER.USER_ID' | translate }}</mat-label>\r
            <input matInput autocomplete="off" formControlName="email" maxlength="10">\r
            <mat-icon matPrefix>person</mat-icon>\r
            <mat-error *ngIf="form.controls.email.errors?.required">\r
              {{ 'LOGIN.FORM.ERROR.USERID_REQUIRED' | translate }}\r
            </mat-error>\r
          </mat-form-field>\r
        </div>\r
        \r
        <div class="form-group">\r
          <mat-form-field class="form-field" appearance="outline">\r
            <mat-label>{{ 'LOGIN.FORM.PLACEHOLDER.PASSWORD' | translate }}</mat-label>\r
            <input matInput autocomplete="off" [type]="hidePassword ? 'password' : 'text'" formControlName="password"\r
              pattern="(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{8,12}" maxlength="12">\r
            <mat-icon matPrefix>lock</mat-icon>\r
            <button mat-icon-button matSuffix type="button" (click)="hidePassword = !hidePassword">\r
              <mat-icon>{{ hidePassword ? 'visibility_off' : 'visibility' }}</mat-icon>\r
            </button>\r
            <mat-error *ngIf="form.controls.password.errors?.required">\r
              {{ 'LOGIN.FORM.ERROR.PASSWORD_REQUIRED' | translate }}\r
            </mat-error>\r
            <mat-error *ngIf="form.controls.password.errors?.pattern">\r
              {{ 'LOGIN.FORM.ERROR.PASSWORD_PATTERN' | translate }}\r
            </mat-error>\r
          </mat-form-field>\r
        </div>\r
        \r
        <!-- CAPTCHA Section -->\r
        <div class="captcha-container">\r
          <div class="captcha-wrapper">\r
            <canvas #captchaCanvas width="140" height="50" class="captcha-canvas"></canvas>\r
            <button mat-icon-button type="button" (click)="generateCaptcha()" class="captcha-refresh" aria-label="Refresh CAPTCHA">\r
              <mat-icon>refresh</mat-icon>\r
            </button>\r
          </div>\r
          <mat-form-field class="form-field captcha-input" appearance="outline">\r
            <mat-label>Enter CAPTCHA</mat-label>\r
            <input matInput autocomplete="off" formControlName="captcha" type="text" maxlength="6">\r
            <mat-icon matPrefix>verified_user</mat-icon>\r
            <mat-error *ngIf="form.get('captcha')?.hasError('required')">\r
              CAPTCHA is required\r
            </mat-error>\r
            <mat-hint *ngIf="form.get('captcha')?.value && !captchaValid" class="captcha-error">\r
              <mat-icon class="hint-icon">cancel</mat-icon> CAPTCHA does not match\r
            </mat-hint>\r
            <mat-hint *ngIf="captchaValid" class="captcha-success">\r
              <mat-icon class="hint-icon">check_circle</mat-icon> CAPTCHA matched\r
            </mat-hint>\r
          </mat-form-field>\r
        </div>\r
        \r
        <button mat-raised-button type="submit" class="login-button" [disabled]="!captchaValid || form.invalid">\r
          {{ 'LOGIN.FORM.BUTTON.SIGNIN' | translate }}\r
        </button>\r
        \r
        <div class="forgot-password-container">\r
          <a (click)="openForgotPassword()" class="forgot-password-link">\r
            {{ 'LOGIN.FORM.FORGOT_PASSWORD' | translate }}\r
          </a>\r
        </div>\r
      </form>\r
    </div>\r
    \r
    <div class="footer">\r
      <p>\xA9 2025 Manappuram Comptech and Consultants Ltd.</p>\r
    </div>\r
  </div>\r
</div>`, styles: ['/* src/app/pages/login/login.component.scss */\n* {\n  margin: 0;\n  padding: 0;\n  box-sizing: border-box;\n}\nbody,\nhtml {\n  margin: 0;\n  padding: 0;\n  height: 100%;\n  overflow-x: hidden;\n  font-family: "Roboto", sans-serif;\n}\n.login-container {\n  display: flex;\n  height: 100vh;\n  width: 100vw;\n  position: fixed;\n  inset: 0;\n}\n.left-panel {\n  width: 60%;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  display: flex;\n  flex-direction: column;\n  justify-content: space-between;\n  padding: 3rem;\n  color: white;\n  position: relative;\n  overflow: hidden;\n}\n.left-panel::before {\n  content: "";\n  position: absolute;\n  inset: 0;\n  background:\n    radial-gradient(\n      circle at 20% 80%,\n      rgba(255, 255, 255, 0.1) 0%,\n      transparent 50%);\n}\n.brand-section {\n  z-index: 1;\n  margin: -3rem -3rem 0 -3rem;\n  padding: 3rem;\n}\n.brand-section .brand-logo {\n  width: 120px;\n  margin-bottom: 2rem;\n  filter: brightness(0) invert(1);\n  margin-top: -50px;\n  max-width: 100%;\n}\n.brand-section .brand-title {\n  font-size: 3.5rem;\n  font-weight: 700;\n  margin-bottom: 0.5rem;\n  text-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);\n}\n.brand-section .brand-subtitle {\n  font-size: 2.5rem;\n  font-weight: 600;\n  margin-bottom: 1rem;\n  opacity: 0.9;\n  color: white;\n}\n.forgot-password-container {\n  text-align: center;\n  margin-bottom: 0.5rem;\n}\n.forgot-password-link {\n  color: #667eea;\n  text-decoration: none;\n  font-weight: 700;\n  cursor: pointer;\n  transition: all 0.3s ease;\n  position: relative;\n}\n.forgot-password-link:hover {\n  color: #764ba2;\n}\n.forgot-password-link::after {\n  content: "";\n  position: absolute;\n  width: 0;\n  height: 2px;\n  bottom: -2px;\n  left: 50%;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  transition: all 0.3s ease;\n  transform: translateX(-50%);\n}\n.forgot-password-link:hover::after {\n  width: 100%;\n}\n.decorative-element {\n  z-index: 1;\n  margin: 0 -3rem -3rem -3rem;\n  padding: 0 3rem 3rem 3rem;\n  margin-bottom: -105px;\n}\n.decorative-element img {\n  width: 200px;\n  opacity: 0.7;\n  filter: brightness(0) invert(1);\n  max-width: 100%;\n}\n.right-panel {\n  width: 40%;\n  background:\n    linear-gradient(\n      135deg,\n      #f5f7fa 0%,\n      #c3cfe2 100%);\n  display: flex;\n  flex-direction: column;\n  justify-content: center;\n  align-items: center;\n  padding: 2rem;\n}\n.login-card {\n  max-height: 640px;\n  background: white;\n  border-radius: 24px;\n  padding: 2rem;\n  width: 90%;\n  max-width: 400px;\n  margin-bottom: 50px;\n  box-shadow: 0 25px 80px rgba(0, 0, 0, 0.15);\n  animation: slideUp 0.8s ease-out;\n}\n.card-header {\n  text-align: center;\n  margin-bottom: 1.2rem;\n}\n.card-header .logo-container {\n  margin-bottom: 0.8rem;\n}\n.card-header .logo-container .app-logo {\n  width: 60px;\n  height: 60px;\n  border-radius: 50%;\n  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);\n}\n.card-header .login-title {\n  font-size: 1.6rem;\n  font-weight: 600;\n  color: #2d3748;\n  margin-bottom: 0.3rem;\n}\n.card-header .login-subtitle {\n  color: #718096;\n  font-size: 0.95rem;\n}\n.login-form .form-group {\n  margin-bottom: 10px;\n}\n.login-form .form-field {\n  width: 100%;\n}\n.login-form .captcha-container {\n  margin-bottom: 0.5rem;\n}\n.login-form .captcha-container .captcha-wrapper {\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  margin-bottom: 1rem;\n  padding: 10px;\n  background:\n    linear-gradient(\n      135deg,\n      #f0f4ff 0%,\n      #e8eeff 100%);\n  border-radius: 12px;\n  border: 2px solid #e2e8f0;\n}\n.login-form .captcha-container .captcha-wrapper .captcha-canvas {\n  border-radius: 8px;\n  background: white;\n  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);\n}\n.login-form .captcha-container .captcha-wrapper .captcha-refresh {\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  color: white;\n  width: 40px;\n  height: 40px;\n  border-radius: 10px;\n  transition: all 0.3s ease;\n}\n.login-form .captcha-container .captcha-wrapper .captcha-refresh:hover {\n  transform: rotate(180deg);\n  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);\n}\n.login-form .captcha-container .captcha-wrapper .captcha-refresh mat-icon {\n  color: white;\n  font-size: 20px;\n}\n.login-form .captcha-container .captcha-input {\n  width: 100%;\n}\n.login-form .captcha-container .captcha-input .captcha-error {\n  color: #ef4444;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  font-weight: 500;\n}\n.login-form .captcha-container .captcha-input .captcha-error .hint-icon {\n  font-size: 16px;\n  width: 16px;\n  height: 16px;\n}\n.login-form .captcha-container .captcha-input .captcha-success {\n  color: #10b981;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  font-weight: 500;\n}\n.login-form .captcha-container .captcha-input .captcha-success .hint-icon {\n  font-size: 16px;\n  width: 16px;\n  height: 16px;\n}\n.login-form .login-button {\n  width: 100%;\n  height: 50px;\n  background:\n    linear-gradient(\n      135deg,\n      #667eea 0%,\n      #764ba2 100%);\n  color: white;\n  border-radius: 12px;\n  font-size: 1rem;\n  font-weight: 600;\n  margin: 0.3rem 0 0.5rem 0;\n  text-transform: none;\n  box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);\n  transition: all 0.3s ease;\n}\n.login-form .login-button:hover:not(:disabled) {\n  transform: translateY(-2px);\n  box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);\n}\n.login-form .login-button:disabled {\n  opacity: 0.6;\n  cursor: not-allowed;\n}\n.footer {\n  position: relative;\n  bottom: 2rem;\n  left: 50%;\n  transform: translateX(-50%);\n  color: #718096;\n  font-size: 0.875rem;\n  text-align: center;\n  white-space: nowrap;\n}\n@media (max-width: 768px) {\n  .login-container {\n    flex-direction: column;\n    height: auto;\n    overflow-y: auto;\n  }\n  .left-panel,\n  .right-panel {\n    width: 100%;\n    padding: 2rem;\n  }\n  .brand-title {\n    font-size: 2.5rem;\n  }\n  .brand-subtitle {\n    font-size: 1.8rem;\n  }\n  .decorative-element {\n    display: none;\n  }\n  .login-card {\n    margin-top: 1rem;\n    max-width: 100%;\n  }\n  .footer {\n    position: static;\n    transform: none;\n    margin-top: 1rem;\n    white-space: normal;\n  }\n}\n@media (max-width: 480px) {\n  .brand-title {\n    font-size: 1.8rem;\n  }\n  .brand-subtitle {\n    font-size: 1.2rem;\n  }\n  .login-card {\n    padding: 1.5rem;\n    margin: 1rem 0;\n  }\n  .login-title {\n    font-size: 1.2rem;\n  }\n  .login-subtitle {\n    font-size: 0.85rem;\n  }\n  .footer {\n    font-size: 0.75rem;\n  }\n}\n@keyframes slideUp {\n  from {\n    opacity: 0;\n    transform: translateY(30px);\n  }\n  to {\n    opacity: 1;\n    transform: translateY(0);\n  }\n}\n', "/* src/app/pages/login/animate.min.scss */\n@-webkit-keyframes bounce {\n  0%, 20%, 53%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  40%, 43% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -30px, 0);\n    transform: translate3d(0, -30px, 0);\n  }\n  70% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -15px, 0);\n    transform: translate3d(0, -15px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -4px, 0);\n    transform: translate3d(0, -4px, 0);\n  }\n}\n@keyframes bounce {\n  0%, 20%, 53%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  40%, 43% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -30px, 0);\n    transform: translate3d(0, -30px, 0);\n  }\n  70% {\n    -webkit-animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    animation-timing-function: cubic-bezier(0.755, 0.05, 0.855, 0.06);\n    -webkit-transform: translate3d(0, -15px, 0);\n    transform: translate3d(0, -15px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -4px, 0);\n    transform: translate3d(0, -4px, 0);\n  }\n}\n.bounce {\n  -webkit-animation-name: bounce;\n  animation-name: bounce;\n  -webkit-transform-origin: center bottom;\n  transform-origin: center bottom;\n}\n@-webkit-keyframes flash {\n  0%, 50%, to {\n    opacity: 1;\n  }\n  25%, 75% {\n    opacity: 0;\n  }\n}\n@keyframes flash {\n  0%, 50%, to {\n    opacity: 1;\n  }\n  25%, 75% {\n    opacity: 0;\n  }\n}\n.flash {\n  -webkit-animation-name: flash;\n  animation-name: flash;\n}\n@-webkit-keyframes pulse {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.05, 1.05, 1.05);\n    transform: scale3d(1.05, 1.05, 1.05);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes pulse {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.05, 1.05, 1.05);\n    transform: scale3d(1.05, 1.05, 1.05);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.pulse {\n  -webkit-animation-name: pulse;\n  animation-name: pulse;\n}\n@-webkit-keyframes rubberBand {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  30% {\n    -webkit-transform: scale3d(1.25, 0.75, 1);\n    transform: scale3d(1.25, 0.75, 1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.75, 1.25, 1);\n    transform: scale3d(0.75, 1.25, 1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.15, 0.85, 1);\n    transform: scale3d(1.15, 0.85, 1);\n  }\n  65% {\n    -webkit-transform: scale3d(0.95, 1.05, 1);\n    transform: scale3d(0.95, 1.05, 1);\n  }\n  75% {\n    -webkit-transform: scale3d(1.05, 0.95, 1);\n    transform: scale3d(1.05, 0.95, 1);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes rubberBand {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  30% {\n    -webkit-transform: scale3d(1.25, 0.75, 1);\n    transform: scale3d(1.25, 0.75, 1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.75, 1.25, 1);\n    transform: scale3d(0.75, 1.25, 1);\n  }\n  50% {\n    -webkit-transform: scale3d(1.15, 0.85, 1);\n    transform: scale3d(1.15, 0.85, 1);\n  }\n  65% {\n    -webkit-transform: scale3d(0.95, 1.05, 1);\n    transform: scale3d(0.95, 1.05, 1);\n  }\n  75% {\n    -webkit-transform: scale3d(1.05, 0.95, 1);\n    transform: scale3d(1.05, 0.95, 1);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.rubberBand {\n  -webkit-animation-name: rubberBand;\n  animation-name: rubberBand;\n}\n@-webkit-keyframes shake {\n  0%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  10%, 30%, 50%, 70%, 90% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  20%, 40%, 60%, 80% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n}\n@keyframes shake {\n  0%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  10%, 30%, 50%, 70%, 90% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  20%, 40%, 60%, 80% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n}\n.shake {\n  -webkit-animation-name: shake;\n  animation-name: shake;\n}\n@-webkit-keyframes headShake {\n  0% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n  6.5% {\n    -webkit-transform: translateX(-6px) rotateY(-9deg);\n    transform: translateX(-6px) rotateY(-9deg);\n  }\n  18.5% {\n    -webkit-transform: translateX(5px) rotateY(7deg);\n    transform: translateX(5px) rotateY(7deg);\n  }\n  31.5% {\n    -webkit-transform: translateX(-3px) rotateY(-5deg);\n    transform: translateX(-3px) rotateY(-5deg);\n  }\n  43.5% {\n    -webkit-transform: translateX(2px) rotateY(3deg);\n    transform: translateX(2px) rotateY(3deg);\n  }\n  50% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n}\n@keyframes headShake {\n  0% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n  6.5% {\n    -webkit-transform: translateX(-6px) rotateY(-9deg);\n    transform: translateX(-6px) rotateY(-9deg);\n  }\n  18.5% {\n    -webkit-transform: translateX(5px) rotateY(7deg);\n    transform: translateX(5px) rotateY(7deg);\n  }\n  31.5% {\n    -webkit-transform: translateX(-3px) rotateY(-5deg);\n    transform: translateX(-3px) rotateY(-5deg);\n  }\n  43.5% {\n    -webkit-transform: translateX(2px) rotateY(3deg);\n    transform: translateX(2px) rotateY(3deg);\n  }\n  50% {\n    -webkit-transform: translateX(0);\n    transform: translateX(0);\n  }\n}\n.headShake {\n  -webkit-animation-timing-function: ease-in-out;\n  animation-timing-function: ease-in-out;\n  -webkit-animation-name: headShake;\n  animation-name: headShake;\n}\n@-webkit-keyframes swing {\n  20% {\n    -webkit-transform: rotate(15deg);\n    transform: rotate(15deg);\n  }\n  40% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  60% {\n    -webkit-transform: rotate(5deg);\n    transform: rotate(5deg);\n  }\n  80% {\n    -webkit-transform: rotate(-5deg);\n    transform: rotate(-5deg);\n  }\n  to {\n    -webkit-transform: rotate(0deg);\n    transform: rotate(0deg);\n  }\n}\n@keyframes swing {\n  20% {\n    -webkit-transform: rotate(15deg);\n    transform: rotate(15deg);\n  }\n  40% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  60% {\n    -webkit-transform: rotate(5deg);\n    transform: rotate(5deg);\n  }\n  80% {\n    -webkit-transform: rotate(-5deg);\n    transform: rotate(-5deg);\n  }\n  to {\n    -webkit-transform: rotate(0deg);\n    transform: rotate(0deg);\n  }\n}\n.swing {\n  -webkit-transform-origin: top center;\n  transform-origin: top center;\n  -webkit-animation-name: swing;\n  animation-name: swing;\n}\n@-webkit-keyframes tada {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  10%, 20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n    transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n  }\n  30%, 50%, 70%, 90% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n  }\n  40%, 60%, 80% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes tada {\n  0% {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n  10%, 20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n    transform: scale3d(0.9, 0.9, 0.9) rotate(-3deg);\n  }\n  30%, 50%, 70%, 90% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(3deg);\n  }\n  40%, 60%, 80% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n    transform: scale3d(1.1, 1.1, 1.1) rotate(-3deg);\n  }\n  to {\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.tada {\n  -webkit-animation-name: tada;\n  animation-name: tada;\n}\n@-webkit-keyframes wobble {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  15% {\n    -webkit-transform: translate3d(-25%, 0, 0) rotate(-5deg);\n    transform: translate3d(-25%, 0, 0) rotate(-5deg);\n  }\n  30% {\n    -webkit-transform: translate3d(20%, 0, 0) rotate(3deg);\n    transform: translate3d(20%, 0, 0) rotate(3deg);\n  }\n  45% {\n    -webkit-transform: translate3d(-15%, 0, 0) rotate(-3deg);\n    transform: translate3d(-15%, 0, 0) rotate(-3deg);\n  }\n  60% {\n    -webkit-transform: translate3d(10%, 0, 0) rotate(2deg);\n    transform: translate3d(10%, 0, 0) rotate(2deg);\n  }\n  75% {\n    -webkit-transform: translate3d(-5%, 0, 0) rotate(-1deg);\n    transform: translate3d(-5%, 0, 0) rotate(-1deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes wobble {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  15% {\n    -webkit-transform: translate3d(-25%, 0, 0) rotate(-5deg);\n    transform: translate3d(-25%, 0, 0) rotate(-5deg);\n  }\n  30% {\n    -webkit-transform: translate3d(20%, 0, 0) rotate(3deg);\n    transform: translate3d(20%, 0, 0) rotate(3deg);\n  }\n  45% {\n    -webkit-transform: translate3d(-15%, 0, 0) rotate(-3deg);\n    transform: translate3d(-15%, 0, 0) rotate(-3deg);\n  }\n  60% {\n    -webkit-transform: translate3d(10%, 0, 0) rotate(2deg);\n    transform: translate3d(10%, 0, 0) rotate(2deg);\n  }\n  75% {\n    -webkit-transform: translate3d(-5%, 0, 0) rotate(-1deg);\n    transform: translate3d(-5%, 0, 0) rotate(-1deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.wobble {\n  -webkit-animation-name: wobble;\n  animation-name: wobble;\n}\n@-webkit-keyframes jello {\n  0%, 11.1%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  22.2% {\n    -webkit-transform: skewX(-12.5deg) skewY(-12.5deg);\n    transform: skewX(-12.5deg) skewY(-12.5deg);\n  }\n  33.3% {\n    -webkit-transform: skewX(6.25deg) skewY(6.25deg);\n    transform: skewX(6.25deg) skewY(6.25deg);\n  }\n  44.4% {\n    -webkit-transform: skewX(-3.125deg) skewY(-3.125deg);\n    transform: skewX(-3.125deg) skewY(-3.125deg);\n  }\n  55.5% {\n    -webkit-transform: skewX(1.5625deg) skewY(1.5625deg);\n    transform: skewX(1.5625deg) skewY(1.5625deg);\n  }\n  66.6% {\n    -webkit-transform: skewX(-0.78125deg) skewY(-0.78125deg);\n    transform: skewX(-0.78125deg) skewY(-0.78125deg);\n  }\n  77.7% {\n    -webkit-transform: skewX(0.390625deg) skewY(0.390625deg);\n    transform: skewX(0.390625deg) skewY(0.390625deg);\n  }\n  88.8% {\n    -webkit-transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n    transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n  }\n}\n@keyframes jello {\n  0%, 11.1%, to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  22.2% {\n    -webkit-transform: skewX(-12.5deg) skewY(-12.5deg);\n    transform: skewX(-12.5deg) skewY(-12.5deg);\n  }\n  33.3% {\n    -webkit-transform: skewX(6.25deg) skewY(6.25deg);\n    transform: skewX(6.25deg) skewY(6.25deg);\n  }\n  44.4% {\n    -webkit-transform: skewX(-3.125deg) skewY(-3.125deg);\n    transform: skewX(-3.125deg) skewY(-3.125deg);\n  }\n  55.5% {\n    -webkit-transform: skewX(1.5625deg) skewY(1.5625deg);\n    transform: skewX(1.5625deg) skewY(1.5625deg);\n  }\n  66.6% {\n    -webkit-transform: skewX(-0.78125deg) skewY(-0.78125deg);\n    transform: skewX(-0.78125deg) skewY(-0.78125deg);\n  }\n  77.7% {\n    -webkit-transform: skewX(0.390625deg) skewY(0.390625deg);\n    transform: skewX(0.390625deg) skewY(0.390625deg);\n  }\n  88.8% {\n    -webkit-transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n    transform: skewX(-0.1953125deg) skewY(-0.1953125deg);\n  }\n}\n.jello {\n  -webkit-animation-name: jello;\n  animation-name: jello;\n  -webkit-transform-origin: center;\n  transform-origin: center;\n}\n@-webkit-keyframes heartBeat {\n  0% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  14% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  28% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  42% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  70% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n@keyframes heartBeat {\n  0% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  14% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  28% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n  42% {\n    -webkit-transform: scale(1.3);\n    transform: scale(1.3);\n  }\n  70% {\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n.heartBeat {\n  -webkit-animation-name: heartBeat;\n  animation-name: heartBeat;\n  -webkit-animation-duration: 1.3s;\n  animation-duration: 1.3s;\n  -webkit-animation-timing-function: ease-in-out;\n  animation-timing-function: ease-in-out;\n}\n@-webkit-keyframes bounceIn {\n  0%, 20%, 40%, 60%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  20% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.03, 1.03, 1.03);\n    transform: scale3d(1.03, 1.03, 1.03);\n  }\n  80% {\n    -webkit-transform: scale3d(0.97, 0.97, 0.97);\n    transform: scale3d(0.97, 0.97, 0.97);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n@keyframes bounceIn {\n  0%, 20%, 40%, 60%, 80%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  20% {\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  40% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.03, 1.03, 1.03);\n    transform: scale3d(1.03, 1.03, 1.03);\n  }\n  80% {\n    -webkit-transform: scale3d(0.97, 0.97, 0.97);\n    transform: scale3d(0.97, 0.97, 0.97);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scaleX(1);\n    transform: scaleX(1);\n  }\n}\n.bounceIn {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: bounceIn;\n  animation-name: bounceIn;\n}\n@-webkit-keyframes bounceInDown {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -3000px, 0);\n    transform: translate3d(0, -3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 25px, 0);\n    transform: translate3d(0, 25px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, 5px, 0);\n    transform: translate3d(0, 5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes bounceInDown {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -3000px, 0);\n    transform: translate3d(0, -3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 25px, 0);\n    transform: translate3d(0, 25px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, 5px, 0);\n    transform: translate3d(0, 5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInDown {\n  -webkit-animation-name: bounceInDown;\n  animation-name: bounceInDown;\n}\n@-webkit-keyframes bounceInLeft {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-3000px, 0, 0);\n    transform: translate3d(-3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(25px, 0, 0);\n    transform: translate3d(25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(5px, 0, 0);\n    transform: translate3d(5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes bounceInLeft {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-3000px, 0, 0);\n    transform: translate3d(-3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(25px, 0, 0);\n    transform: translate3d(25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(-10px, 0, 0);\n    transform: translate3d(-10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(5px, 0, 0);\n    transform: translate3d(5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInLeft {\n  -webkit-animation-name: bounceInLeft;\n  animation-name: bounceInLeft;\n}\n@-webkit-keyframes bounceInRight {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(3000px, 0, 0);\n    transform: translate3d(3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(-25px, 0, 0);\n    transform: translate3d(-25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(-5px, 0, 0);\n    transform: translate3d(-5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes bounceInRight {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(3000px, 0, 0);\n    transform: translate3d(3000px, 0, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(-25px, 0, 0);\n    transform: translate3d(-25px, 0, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(10px, 0, 0);\n    transform: translate3d(10px, 0, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(-5px, 0, 0);\n    transform: translate3d(-5px, 0, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInRight {\n  -webkit-animation-name: bounceInRight;\n  animation-name: bounceInRight;\n}\n@-webkit-keyframes bounceInUp {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 3000px, 0);\n    transform: translate3d(0, 3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -5px, 0);\n    transform: translate3d(0, -5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes bounceInUp {\n  0%, 60%, 75%, 90%, to {\n    -webkit-animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n    animation-timing-function: cubic-bezier(0.215, 0.61, 0.355, 1);\n  }\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 3000px, 0);\n    transform: translate3d(0, 3000px, 0);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  75% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  90% {\n    -webkit-transform: translate3d(0, -5px, 0);\n    transform: translate3d(0, -5px, 0);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.bounceInUp {\n  -webkit-animation-name: bounceInUp;\n  animation-name: bounceInUp;\n}\n@-webkit-keyframes bounceOut {\n  20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  50%, 55% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n}\n@keyframes bounceOut {\n  20% {\n    -webkit-transform: scale3d(0.9, 0.9, 0.9);\n    transform: scale3d(0.9, 0.9, 0.9);\n  }\n  50%, 55% {\n    opacity: 1;\n    -webkit-transform: scale3d(1.1, 1.1, 1.1);\n    transform: scale3d(1.1, 1.1, 1.1);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n}\n.bounceOut {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: bounceOut;\n  animation-name: bounceOut;\n}\n@-webkit-keyframes bounceOutDown {\n  20% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n@keyframes bounceOutDown {\n  20% {\n    -webkit-transform: translate3d(0, 10px, 0);\n    transform: translate3d(0, 10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, -20px, 0);\n    transform: translate3d(0, -20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n.bounceOutDown {\n  -webkit-animation-name: bounceOutDown;\n  animation-name: bounceOutDown;\n}\n@-webkit-keyframes bounceOutLeft {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(20px, 0, 0);\n    transform: translate3d(20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n@keyframes bounceOutLeft {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(20px, 0, 0);\n    transform: translate3d(20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n.bounceOutLeft {\n  -webkit-animation-name: bounceOutLeft;\n  animation-name: bounceOutLeft;\n}\n@-webkit-keyframes bounceOutRight {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(-20px, 0, 0);\n    transform: translate3d(-20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n@keyframes bounceOutRight {\n  20% {\n    opacity: 1;\n    -webkit-transform: translate3d(-20px, 0, 0);\n    transform: translate3d(-20px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n.bounceOutRight {\n  -webkit-animation-name: bounceOutRight;\n  animation-name: bounceOutRight;\n}\n@-webkit-keyframes bounceOutUp {\n  20% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 20px, 0);\n    transform: translate3d(0, 20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n@keyframes bounceOutUp {\n  20% {\n    -webkit-transform: translate3d(0, -10px, 0);\n    transform: translate3d(0, -10px, 0);\n  }\n  40%, 45% {\n    opacity: 1;\n    -webkit-transform: translate3d(0, 20px, 0);\n    transform: translate3d(0, 20px, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n.bounceOutUp {\n  -webkit-animation-name: bounceOutUp;\n  animation-name: bounceOutUp;\n}\n@-webkit-keyframes fadeIn {\n  0% {\n    opacity: 0;\n  }\n  to {\n    opacity: 1;\n  }\n}\n@keyframes fadeIn {\n  0% {\n    opacity: 0;\n  }\n  to {\n    opacity: 1;\n  }\n}\n.fadeIn {\n  -webkit-animation-name: fadeIn;\n  animation-name: fadeIn;\n}\n@-webkit-keyframes fadeInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInDown {\n  -webkit-animation-name: fadeInDown;\n  animation-name: fadeInDown;\n}\n@-webkit-keyframes fadeInDownBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInDownBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInDownBig {\n  -webkit-animation-name: fadeInDownBig;\n  animation-name: fadeInDownBig;\n}\n@-webkit-keyframes fadeInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInLeft {\n  -webkit-animation-name: fadeInLeft;\n  animation-name: fadeInLeft;\n}\n@-webkit-keyframes fadeInLeftBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInLeftBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInLeftBig {\n  -webkit-animation-name: fadeInLeftBig;\n  animation-name: fadeInLeftBig;\n}\n@-webkit-keyframes fadeInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInRight {\n  -webkit-animation-name: fadeInRight;\n  animation-name: fadeInRight;\n}\n@-webkit-keyframes fadeInRightBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInRightBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInRightBig {\n  -webkit-animation-name: fadeInRightBig;\n  animation-name: fadeInRightBig;\n}\n@-webkit-keyframes fadeInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInUp {\n  -webkit-animation-name: fadeInUp;\n  animation-name: fadeInUp;\n}\n@-webkit-keyframes fadeInUpBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes fadeInUpBig {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.fadeInUpBig {\n  -webkit-animation-name: fadeInUpBig;\n  animation-name: fadeInUpBig;\n}\n@-webkit-keyframes fadeOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n  }\n}\n@keyframes fadeOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n  }\n}\n.fadeOut {\n  -webkit-animation-name: fadeOut;\n  animation-name: fadeOut;\n}\n@-webkit-keyframes fadeOutDown {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n@keyframes fadeOutDown {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n.fadeOutDown {\n  -webkit-animation-name: fadeOutDown;\n  animation-name: fadeOutDown;\n}\n@-webkit-keyframes fadeOutDownBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n@keyframes fadeOutDownBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, 2000px, 0);\n    transform: translate3d(0, 2000px, 0);\n  }\n}\n.fadeOutDownBig {\n  -webkit-animation-name: fadeOutDownBig;\n  animation-name: fadeOutDownBig;\n}\n@-webkit-keyframes fadeOutLeft {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n@keyframes fadeOutLeft {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n.fadeOutLeft {\n  -webkit-animation-name: fadeOutLeft;\n  animation-name: fadeOutLeft;\n}\n@-webkit-keyframes fadeOutLeftBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n@keyframes fadeOutLeftBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(-2000px, 0, 0);\n    transform: translate3d(-2000px, 0, 0);\n  }\n}\n.fadeOutLeftBig {\n  -webkit-animation-name: fadeOutLeftBig;\n  animation-name: fadeOutLeftBig;\n}\n@-webkit-keyframes fadeOutRight {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n@keyframes fadeOutRight {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n.fadeOutRight {\n  -webkit-animation-name: fadeOutRight;\n  animation-name: fadeOutRight;\n}\n@-webkit-keyframes fadeOutRightBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n@keyframes fadeOutRightBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(2000px, 0, 0);\n    transform: translate3d(2000px, 0, 0);\n  }\n}\n.fadeOutRightBig {\n  -webkit-animation-name: fadeOutRightBig;\n  animation-name: fadeOutRightBig;\n}\n@-webkit-keyframes fadeOutUp {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n@keyframes fadeOutUp {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n.fadeOutUp {\n  -webkit-animation-name: fadeOutUp;\n  animation-name: fadeOutUp;\n}\n@-webkit-keyframes fadeOutUpBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n@keyframes fadeOutUpBig {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(0, -2000px, 0);\n    transform: translate3d(0, -2000px, 0);\n  }\n}\n.fadeOutUpBig {\n  -webkit-animation-name: fadeOutUpBig;\n  animation-name: fadeOutUpBig;\n}\n@-webkit-keyframes flip {\n  0% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  40% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  50% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  80% {\n    -webkit-transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  to {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n}\n@keyframes flip {\n  0% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(-1turn);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  40% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-190deg);\n    -webkit-animation-timing-function: ease-out;\n    animation-timing-function: ease-out;\n  }\n  50% {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    transform: perspective(400px) scaleX(1) translateZ(150px) rotateY(-170deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  80% {\n    -webkit-transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scale3d(0.95, 0.95, 0.95) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  to {\n    -webkit-transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    transform: perspective(400px) scaleX(1) translateZ(0) rotateY(0deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n}\n.animated.flip {\n  -webkit-backface-visibility: visible;\n  backface-visibility: visible;\n  -webkit-animation-name: flip;\n  animation-name: flip;\n}\n@-webkit-keyframes flipInX {\n  0% {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateX(10deg);\n    transform: perspective(400px) rotateX(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateX(-5deg);\n    transform: perspective(400px) rotateX(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n@keyframes flipInX {\n  0% {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateX(10deg);\n    transform: perspective(400px) rotateX(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateX(-5deg);\n    transform: perspective(400px) rotateX(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n.flipInX {\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: flipInX;\n  animation-name: flipInX;\n}\n@-webkit-keyframes flipInY {\n  0% {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateY(-20deg);\n    transform: perspective(400px) rotateY(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateY(10deg);\n    transform: perspective(400px) rotateY(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateY(-5deg);\n    transform: perspective(400px) rotateY(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n@keyframes flipInY {\n  0% {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n    opacity: 0;\n  }\n  40% {\n    -webkit-transform: perspective(400px) rotateY(-20deg);\n    transform: perspective(400px) rotateY(-20deg);\n    -webkit-animation-timing-function: ease-in;\n    animation-timing-function: ease-in;\n  }\n  60% {\n    -webkit-transform: perspective(400px) rotateY(10deg);\n    transform: perspective(400px) rotateY(10deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: perspective(400px) rotateY(-5deg);\n    transform: perspective(400px) rotateY(-5deg);\n  }\n  to {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n}\n.flipInY {\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: flipInY;\n  animation-name: flipInY;\n}\n@-webkit-keyframes flipOutX {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    opacity: 0;\n  }\n}\n@keyframes flipOutX {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateX(-20deg);\n    transform: perspective(400px) rotateX(-20deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateX(90deg);\n    transform: perspective(400px) rotateX(90deg);\n    opacity: 0;\n  }\n}\n.flipOutX {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-animation-name: flipOutX;\n  animation-name: flipOutX;\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n}\n@-webkit-keyframes flipOutY {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateY(-15deg);\n    transform: perspective(400px) rotateY(-15deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    opacity: 0;\n  }\n}\n@keyframes flipOutY {\n  0% {\n    -webkit-transform: perspective(400px);\n    transform: perspective(400px);\n  }\n  30% {\n    -webkit-transform: perspective(400px) rotateY(-15deg);\n    transform: perspective(400px) rotateY(-15deg);\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: perspective(400px) rotateY(90deg);\n    transform: perspective(400px) rotateY(90deg);\n    opacity: 0;\n  }\n}\n.flipOutY {\n  -webkit-animation-duration: 0.75s;\n  animation-duration: 0.75s;\n  -webkit-backface-visibility: visible !important;\n  backface-visibility: visible !important;\n  -webkit-animation-name: flipOutY;\n  animation-name: flipOutY;\n}\n@-webkit-keyframes lightSpeedIn {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(-30deg);\n    transform: translate3d(100%, 0, 0) skewX(-30deg);\n    opacity: 0;\n  }\n  60% {\n    -webkit-transform: skewX(20deg);\n    transform: skewX(20deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: skewX(-5deg);\n    transform: skewX(-5deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes lightSpeedIn {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(-30deg);\n    transform: translate3d(100%, 0, 0) skewX(-30deg);\n    opacity: 0;\n  }\n  60% {\n    -webkit-transform: skewX(20deg);\n    transform: skewX(20deg);\n    opacity: 1;\n  }\n  80% {\n    -webkit-transform: skewX(-5deg);\n    transform: skewX(-5deg);\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.lightSpeedIn {\n  -webkit-animation-name: lightSpeedIn;\n  animation-name: lightSpeedIn;\n  -webkit-animation-timing-function: ease-out;\n  animation-timing-function: ease-out;\n}\n@-webkit-keyframes lightSpeedOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(30deg);\n    transform: translate3d(100%, 0, 0) skewX(30deg);\n    opacity: 0;\n  }\n}\n@keyframes lightSpeedOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(100%, 0, 0) skewX(30deg);\n    transform: translate3d(100%, 0, 0) skewX(30deg);\n    opacity: 0;\n  }\n}\n.lightSpeedOut {\n  -webkit-animation-name: lightSpeedOut;\n  animation-name: lightSpeedOut;\n  -webkit-animation-timing-function: ease-in;\n  animation-timing-function: ease-in;\n}\n@-webkit-keyframes rotateIn {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(-200deg);\n    transform: rotate(-200deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes rotateIn {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(-200deg);\n    transform: rotate(-200deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateIn {\n  -webkit-animation-name: rotateIn;\n  animation-name: rotateIn;\n}\n@-webkit-keyframes rotateInDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes rotateInDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInDownLeft {\n  -webkit-animation-name: rotateInDownLeft;\n  animation-name: rotateInDownLeft;\n}\n@-webkit-keyframes rotateInDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes rotateInDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInDownRight {\n  -webkit-animation-name: rotateInDownRight;\n  animation-name: rotateInDownRight;\n}\n@-webkit-keyframes rotateInUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes rotateInUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInUpLeft {\n  -webkit-animation-name: rotateInUpLeft;\n  animation-name: rotateInUpLeft;\n}\n@-webkit-keyframes rotateInUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-90deg);\n    transform: rotate(-90deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n@keyframes rotateInUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-90deg);\n    transform: rotate(-90deg);\n    opacity: 0;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n    opacity: 1;\n  }\n}\n.rotateInUpRight {\n  -webkit-animation-name: rotateInUpRight;\n  animation-name: rotateInUpRight;\n}\n@-webkit-keyframes rotateOut {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(200deg);\n    transform: rotate(200deg);\n    opacity: 0;\n  }\n}\n@keyframes rotateOut {\n  0% {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: center;\n    transform-origin: center;\n    -webkit-transform: rotate(200deg);\n    transform: rotate(200deg);\n    opacity: 0;\n  }\n}\n.rotateOut {\n  -webkit-animation-name: rotateOut;\n  animation-name: rotateOut;\n}\n@-webkit-keyframes rotateOutDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n}\n@keyframes rotateOutDownLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(45deg);\n    transform: rotate(45deg);\n    opacity: 0;\n  }\n}\n.rotateOutDownLeft {\n  -webkit-animation-name: rotateOutDownLeft;\n  animation-name: rotateOutDownLeft;\n}\n@-webkit-keyframes rotateOutDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n@keyframes rotateOutDownRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n.rotateOutDownRight {\n  -webkit-animation-name: rotateOutDownRight;\n  animation-name: rotateOutDownRight;\n}\n@-webkit-keyframes rotateOutUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n@keyframes rotateOutUpLeft {\n  0% {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: left bottom;\n    transform-origin: left bottom;\n    -webkit-transform: rotate(-45deg);\n    transform: rotate(-45deg);\n    opacity: 0;\n  }\n}\n.rotateOutUpLeft {\n  -webkit-animation-name: rotateOutUpLeft;\n  animation-name: rotateOutUpLeft;\n}\n@-webkit-keyframes rotateOutUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(90deg);\n    transform: rotate(90deg);\n    opacity: 0;\n  }\n}\n@keyframes rotateOutUpRight {\n  0% {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform-origin: right bottom;\n    transform-origin: right bottom;\n    -webkit-transform: rotate(90deg);\n    transform: rotate(90deg);\n    opacity: 0;\n  }\n}\n.rotateOutUpRight {\n  -webkit-animation-name: rotateOutUpRight;\n  animation-name: rotateOutUpRight;\n}\n@-webkit-keyframes hinge {\n  0% {\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  20%, 60% {\n    -webkit-transform: rotate(80deg);\n    transform: rotate(80deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  40%, 80% {\n    -webkit-transform: rotate(60deg);\n    transform: rotate(60deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(0, 700px, 0);\n    transform: translate3d(0, 700px, 0);\n    opacity: 0;\n  }\n}\n@keyframes hinge {\n  0% {\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  20%, 60% {\n    -webkit-transform: rotate(80deg);\n    transform: rotate(80deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n  }\n  40%, 80% {\n    -webkit-transform: rotate(60deg);\n    transform: rotate(60deg);\n    -webkit-transform-origin: top left;\n    transform-origin: top left;\n    -webkit-animation-timing-function: ease-in-out;\n    animation-timing-function: ease-in-out;\n    opacity: 1;\n  }\n  to {\n    -webkit-transform: translate3d(0, 700px, 0);\n    transform: translate3d(0, 700px, 0);\n    opacity: 0;\n  }\n}\n.hinge {\n  -webkit-animation-duration: 2s;\n  animation-duration: 2s;\n  -webkit-animation-name: hinge;\n  animation-name: hinge;\n}\n@-webkit-keyframes jackInTheBox {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale(0.1) rotate(30deg);\n    transform: scale(0.1) rotate(30deg);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n  }\n  50% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  70% {\n    -webkit-transform: rotate(3deg);\n    transform: rotate(3deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n@keyframes jackInTheBox {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale(0.1) rotate(30deg);\n    transform: scale(0.1) rotate(30deg);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n  }\n  50% {\n    -webkit-transform: rotate(-10deg);\n    transform: rotate(-10deg);\n  }\n  70% {\n    -webkit-transform: rotate(3deg);\n    transform: rotate(3deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: scale(1);\n    transform: scale(1);\n  }\n}\n.jackInTheBox {\n  -webkit-animation-name: jackInTheBox;\n  animation-name: jackInTheBox;\n}\n@-webkit-keyframes rollIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0) rotate(-120deg);\n    transform: translate3d(-100%, 0, 0) rotate(-120deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes rollIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: translate3d(-100%, 0, 0) rotate(-120deg);\n    transform: translate3d(-100%, 0, 0) rotate(-120deg);\n  }\n  to {\n    opacity: 1;\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.rollIn {\n  -webkit-animation-name: rollIn;\n  animation-name: rollIn;\n}\n@-webkit-keyframes rollOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0) rotate(120deg);\n    transform: translate3d(100%, 0, 0) rotate(120deg);\n  }\n}\n@keyframes rollOut {\n  0% {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: translate3d(100%, 0, 0) rotate(120deg);\n    transform: translate3d(100%, 0, 0) rotate(120deg);\n  }\n}\n.rollOut {\n  -webkit-animation-name: rollOut;\n  animation-name: rollOut;\n}\n@-webkit-keyframes zoomIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  50% {\n    opacity: 1;\n  }\n}\n@keyframes zoomIn {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  50% {\n    opacity: 1;\n  }\n}\n.zoomIn {\n  -webkit-animation-name: zoomIn;\n  animation-name: zoomIn;\n}\n@-webkit-keyframes zoomInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomInDown {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInDown {\n  -webkit-animation-name: zoomInDown;\n  animation-name: zoomInDown;\n}\n@-webkit-keyframes zoomInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomInLeft {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(-1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInLeft {\n  -webkit-animation-name: zoomInLeft;\n  animation-name: zoomInLeft;\n}\n@-webkit-keyframes zoomInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomInRight {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(1000px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-10px, 0, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInRight {\n  -webkit-animation-name: zoomInRight;\n  animation-name: zoomInRight;\n}\n@-webkit-keyframes zoomInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomInUp {\n  0% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 1000px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  60% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomInUp {\n  -webkit-animation-name: zoomInUp;\n  animation-name: zoomInUp;\n}\n@-webkit-keyframes zoomOut {\n  0% {\n    opacity: 1;\n  }\n  50% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  to {\n    opacity: 0;\n  }\n}\n@keyframes zoomOut {\n  0% {\n    opacity: 1;\n  }\n  50% {\n    opacity: 0;\n    -webkit-transform: scale3d(0.3, 0.3, 0.3);\n    transform: scale3d(0.3, 0.3, 0.3);\n  }\n  to {\n    opacity: 0;\n  }\n}\n.zoomOut {\n  -webkit-animation-name: zoomOut;\n  animation-name: zoomOut;\n}\n@-webkit-keyframes zoomOutDown {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomOutDown {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, -60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, 2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomOutDown {\n  -webkit-animation-name: zoomOutDown;\n  animation-name: zoomOutDown;\n}\n@-webkit-keyframes zoomOutLeft {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(-2000px, 0, 0);\n    transform: scale(0.1) translate3d(-2000px, 0, 0);\n    -webkit-transform-origin: left center;\n    transform-origin: left center;\n  }\n}\n@keyframes zoomOutLeft {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(-2000px, 0, 0);\n    transform: scale(0.1) translate3d(-2000px, 0, 0);\n    -webkit-transform-origin: left center;\n    transform-origin: left center;\n  }\n}\n.zoomOutLeft {\n  -webkit-animation-name: zoomOutLeft;\n  animation-name: zoomOutLeft;\n}\n@-webkit-keyframes zoomOutRight {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(2000px, 0, 0);\n    transform: scale(0.1) translate3d(2000px, 0, 0);\n    -webkit-transform-origin: right center;\n    transform-origin: right center;\n  }\n}\n@keyframes zoomOutRight {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(-42px, 0, 0);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale(0.1) translate3d(2000px, 0, 0);\n    transform: scale(0.1) translate3d(2000px, 0, 0);\n    -webkit-transform-origin: right center;\n    transform-origin: right center;\n  }\n}\n.zoomOutRight {\n  -webkit-animation-name: zoomOutRight;\n  animation-name: zoomOutRight;\n}\n@-webkit-keyframes zoomOutUp {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n@keyframes zoomOutUp {\n  40% {\n    opacity: 1;\n    -webkit-transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    transform: scale3d(0.475, 0.475, 0.475) translate3d(0, 60px, 0);\n    -webkit-animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n    animation-timing-function: cubic-bezier(0.55, 0.055, 0.675, 0.19);\n  }\n  to {\n    opacity: 0;\n    -webkit-transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    transform: scale3d(0.1, 0.1, 0.1) translate3d(0, -2000px, 0);\n    -webkit-transform-origin: center bottom;\n    transform-origin: center bottom;\n    -webkit-animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n    animation-timing-function: cubic-bezier(0.175, 0.885, 0.32, 1);\n  }\n}\n.zoomOutUp {\n  -webkit-animation-name: zoomOutUp;\n  animation-name: zoomOutUp;\n}\n@-webkit-keyframes slideInDown {\n  0% {\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes slideInDown {\n  0% {\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInDown {\n  -webkit-animation-name: slideInDown;\n  animation-name: slideInDown;\n}\n@-webkit-keyframes slideInLeft {\n  0% {\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes slideInLeft {\n  0% {\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInLeft {\n  -webkit-animation-name: slideInLeft;\n  animation-name: slideInLeft;\n}\n@-webkit-keyframes slideInRight {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes slideInRight {\n  0% {\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInRight {\n  -webkit-animation-name: slideInRight;\n  animation-name: slideInRight;\n}\n@-webkit-keyframes slideInUp {\n  0% {\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n@keyframes slideInUp {\n  0% {\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n    visibility: visible;\n  }\n  to {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n}\n.slideInUp {\n  -webkit-animation-name: slideInUp;\n  animation-name: slideInUp;\n}\n@-webkit-keyframes slideOutDown {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n@keyframes slideOutDown {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, 100%, 0);\n    transform: translate3d(0, 100%, 0);\n  }\n}\n.slideOutDown {\n  -webkit-animation-name: slideOutDown;\n  animation-name: slideOutDown;\n}\n@-webkit-keyframes slideOutLeft {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n@keyframes slideOutLeft {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(-100%, 0, 0);\n    transform: translate3d(-100%, 0, 0);\n  }\n}\n.slideOutLeft {\n  -webkit-animation-name: slideOutLeft;\n  animation-name: slideOutLeft;\n}\n@-webkit-keyframes slideOutRight {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n@keyframes slideOutRight {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(100%, 0, 0);\n    transform: translate3d(100%, 0, 0);\n  }\n}\n.slideOutRight {\n  -webkit-animation-name: slideOutRight;\n  animation-name: slideOutRight;\n}\n@-webkit-keyframes slideOutUp {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n@keyframes slideOutUp {\n  0% {\n    -webkit-transform: translateZ(0);\n    transform: translateZ(0);\n  }\n  to {\n    visibility: hidden;\n    -webkit-transform: translate3d(0, -100%, 0);\n    transform: translate3d(0, -100%, 0);\n  }\n}\n.slideOutUp {\n  -webkit-animation-name: slideOutUp;\n  animation-name: slideOutUp;\n}\n.animated {\n  -webkit-animation-duration: 1s;\n  animation-duration: 1s;\n  -webkit-animation-fill-mode: both;\n  animation-fill-mode: both;\n}\n.animated.infinite {\n  -webkit-animation-iteration-count: infinite;\n  animation-iteration-count: infinite;\n}\n.animated.delay-1s {\n  -webkit-animation-delay: 1s;\n  animation-delay: 1s;\n}\n.animated.delay-2s {\n  -webkit-animation-delay: 2s;\n  animation-delay: 2s;\n}\n.animated.delay-3s {\n  -webkit-animation-delay: 3s;\n  animation-delay: 3s;\n}\n.animated.delay-4s {\n  -webkit-animation-delay: 4s;\n  animation-delay: 4s;\n}\n.animated.delay-5s {\n  -webkit-animation-delay: 5s;\n  animation-delay: 5s;\n}\n.animated.fast {\n  -webkit-animation-duration: 0.8s;\n  animation-duration: 0.8s;\n}\n.animated.faster {\n  -webkit-animation-duration: 0.5s;\n  animation-duration: 0.5s;\n}\n.animated.slow {\n  -webkit-animation-duration: 2s;\n  animation-duration: 2s;\n}\n.animated.slower {\n  -webkit-animation-duration: 3s;\n  animation-duration: 3s;\n}\n@media (prefers-reduced-motion: reduce), (print) {\n  .animated {\n    -webkit-animation-duration: 1ms !important;\n    animation-duration: 1ms !important;\n    -webkit-transition-duration: 1ms !important;\n    transition-duration: 1ms !important;\n    -webkit-animation-iteration-count: 1 !important;\n    animation-iteration-count: 1 !important;\n  }\n}\n/*!\n * animate.css -https://daneden.github.io/animate.css/\n * Version - 3.7.2\n * Licensed under the MIT license - http://opensource.org/licenses/MIT\n *\n * Copyright (c) 2019 Daniel Eden\n */\n"] }]
  }], () => [{ type: NgZone }, { type: MatDialog }, { type: AppSettings }, { type: UntypedFormBuilder }, { type: Router }, { type: ActivatedRoute }, { type: DestroyRef }, { type: CommonService }, { type: CommonSharedService }, { type: Sec }, { type: AuthenticationService }, { type: AlertService }, { type: TranslateService }, { type: ShieldService }, { type: CustomerService }, { type: MatSnackBar }, { type: BrandingService }, { type: SessionTimeoutService }], { canvasRef: [{
    type: ViewChild,
    args: ["captchaCanvas", { static: true }]
  }] });
})();
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && \u0275setClassDebugInfo(LoginComponent, { className: "LoginComponent", filePath: "src/app/pages/login/login.component.ts", lineNumber: 40 });
})();

export {
  ResetPasswordComponent,
  ForgotPasswordComponent,
  LoginComponent
};
