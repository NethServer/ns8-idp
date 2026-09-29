<!--
  Copyright (C) 2026 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getConfiguration">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-configuration')"
          :description="error.getConfiguration"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-form @submit.prevent="configureModule">
            <NsTextInput
              :label="$t('settings.host')"
              :placeholder="$t('settings.host_placeholder')"
              v-model.trim="host"
              :invalid-message="error.host"
              :disabled="loadingUi"
              ref="host"
            >
              <template #tooltip>
                {{ $t("settings.host_tooltip") }}
              </template>
            </NsTextInput>
            <NsToggle
              value="letsEncrypt"
              :label="core.$t('apps_lets_encrypt.request_https_certificate')"
              v-model="isLetsEncryptEnabled"
              :disabled="loadingUi"
            >
              <template #tooltip>
                <div class="mg-bottom-sm">
                  {{ core.$t("apps_lets_encrypt.lets_encrypt_tips") }}
                </div>
                <div class="mg-bottom-sm">
                  <cv-link @click="goToCertificates">
                    {{ core.$t("apps_lets_encrypt.go_to_tls_certificates") }}
                  </cv-link>
                </div>
              </template>
              <template slot="text-left">{{
                $t("settings.disabled")
              }}</template>
              <template slot="text-right">{{
                $t("settings.enabled")
              }}</template>
            </NsToggle>
            <cv-row
              v-if="isLetsEncryptCurrentlyEnabled && !isLetsEncryptEnabled"
            >
              <cv-column>
                <NsInlineNotification
                  kind="warning"
                  :title="
                    core.$t('apps_lets_encrypt.lets_encrypt_disabled_warning')
                  "
                  :description="
                    core.$t(
                      'apps_lets_encrypt.lets_encrypt_disabled_warning_description',
                      { node: nodeLabel }
                    )
                  "
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <cv-row v-if="error.getStatus">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="$t('action.get-status')"
                  :description="error.getStatus"
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <cv-row v-if="certificateErrorDetails.length">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="
                    core.$t('apps_lets_encrypt.cannot_obtain_certificate')
                  "
                  :showCloseButton="false"
                >
                  <template #description>
                    <div
                      v-for="(detail, index) in certificateErrorDetails"
                      :key="index"
                    >
                      {{ detail }}
                    </div>
                  </template>
                </NsInlineNotification>
              </cv-column>
            </cv-row>
            <cv-row v-if="error.configureModule">
              <cv-column>
                <NsInlineNotification
                  kind="error"
                  :title="$t('action.configure-module')"
                  :description="error.configureModule"
                  :showCloseButton="false"
                />
              </cv-column>
            </cv-row>
            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="loadingUi"
              >{{ $t("settings.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import to from "await-to-js";
import { mapState } from "vuex";
import {
  QueryParamService,
  UtilService,
  TaskService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";

export default {
  name: "Settings",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "settings",
      },
      urlCheckInterval: null,
      host: "",
      isLetsEncryptEnabled: false,
      isLetsEncryptCurrentlyEnabled: false,
      status: {},
      certificateErrorDetails: [],
      loading: {
        getConfiguration: false,
        getStatus: false,
        configureModule: false,
      },
      error: {
        getConfiguration: "",
        getStatus: "",
        configureModule: "",
        host: "",
        lets_encrypt: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    loadingUi() {
      return (
        this.loading.getConfiguration ||
        this.loading.getStatus ||
        this.loading.configureModule
      );
    },
    nodeLabel() {
      return this.status.node_ui_name || this.status.node || "";
    },
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  created() {
    this.getConfiguration();
    this.getStatus();
  },
  methods: {
    goToCertificates() {
      this.core.$router.push("/settings/tls-certificates");
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getConfigurationAborted
      );

      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getConfigurationCompleted
      );

      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];

      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.getConfiguration = this.getErrorMessage(err);
        this.loading.getConfiguration = false;
        return;
      }
    },
    getConfigurationAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.getConfiguration = this.$t("error.generic_error");
      this.loading.getConfiguration = false;
    },
    getConfigurationCompleted(taskContext, taskResult) {
      const config = taskResult.output;
      this.host = config.host;
      this.isLetsEncryptEnabled = config.lets_encrypt;
      this.isLetsEncryptCurrentlyEnabled = config.lets_encrypt;
      this.loading.getConfiguration = false;
      this.focusElement("host");
    },
    async getStatus() {
      this.loading.getStatus = true;
      this.error.getStatus = "";
      const taskAction = "get-status";
      const eventId = this.getUuid();

      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getStatusAborted
      );

      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getStatusCompleted
      );

      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
      const err = res[0];

      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.getStatus = this.getErrorMessage(err);
        this.loading.getStatus = false;
        return;
      }
    },
    getStatusAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.getStatus = this.$t("error.generic_error");
      this.loading.getStatus = false;
    },
    getStatusCompleted(taskContext, taskResult) {
      this.status = taskResult.output;
      this.loading.getStatus = false;
    },
    validateConfigureModule() {
      this.clearErrors(this);
      this.certificateErrorDetails = [];

      if (!this.host) {
        this.error.host = this.$t("common.required");
        this.focusElement("host");
        return false;
      }
      return true;
    },
    configureModuleValidationFailed(validationErrors) {
      this.loading.configureModule = false;
      let focusAlreadySet = false;

      for (const validationError of validationErrors) {
        if (validationError.details) {
          // Traefik cannot obtain the Let's Encrypt certificate: show
          // its messages in an inline notification
          this.certificateErrorDetails = validationError.details
            .split("\n")
            .filter((detail) => detail.trim() !== "");
          continue;
        }
        const param = validationError.parameter;

        if (param in this.error) {
          // set i18n error message
          this.error[param] = this.$t("settings." + validationError.error);

          if (!focusAlreadySet) {
            this.focusElement(param);
            focusAlreadySet = true;
          }
        }
      }
    },
    async configureModule() {
      if (!this.validateConfigureModule()) {
        return;
      }

      this.loading.configureModule = true;
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      // register to task error
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.configureModuleAborted
      );

      // register to task validation
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.configureModuleValidationFailed
      );

      // register to task completion
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.configureModuleCompleted
      );

      const res = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            host: this.host,
            lets_encrypt: this.isLetsEncryptEnabled,
          },
          extra: {
            title: this.$t("settings.configure_instance", {
              instance: this.instanceName,
            }),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );
      const err = res[0];

      if (err) {
        console.error(`error creating task ${taskAction}`, err);
        this.error.configureModule = this.getErrorMessage(err);
        this.loading.configureModule = false;
        return;
      }
    },
    configureModuleAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.error.configureModule = this.$t("error.generic_error");
      this.loading.configureModule = false;
    },
    configureModuleCompleted() {
      this.loading.configureModule = false;

      // reload configuration
      this.getConfiguration();
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.cv-form .bx--form-item {
  margin-bottom: $spacing-06;
}
</style>
