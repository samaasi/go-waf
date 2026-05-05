package k8s

import (
	"context"
	"fmt"

	"github.com/samaasi/go-waf/internal/domain"
	
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type PolicyWatcher struct {
	client  *rest.RESTClient
	logger  domain.Logger
	handler func(policy *WafPolicy)
}

func NewPolicyWatcher(logger domain.Logger, handler func(policy *WafPolicy)) (*PolicyWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to local kubeconfig for development if needed, 
		// but in production this runs inside K8s.
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	scheme := runtime.NewScheme()
	gv := schema.GroupVersion{Group: "security.snapwaf.com", Version: "v1"}
	scheme.AddKnownTypes(gv, &WafPolicy{}, &WafPolicyList{})

	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme).WithoutConversion()

	client, err := rest.RESTClientFor(config)
	if err != nil {
		return nil, err
	}

	return &PolicyWatcher{
		client:  client,
		logger:  logger,
		handler: handler,
	}, nil
}

func (w *PolicyWatcher) Start(ctx context.Context) {
	watchlist := cache.NewListWatchFromClient(w.client, "wafpolicies", "", nil)

	_, controller := cache.NewInformer(
		watchlist,
		&WafPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				policy := obj.(*WafPolicy)
				w.logger.Info("New WafPolicy detected", domain.String("name", policy.Name))
				w.handler(policy)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				policy := newObj.(*WafPolicy)
				w.logger.Info("WafPolicy updated", domain.String("name", policy.Name))
				w.handler(policy)
			},
			DeleteFunc: func(obj interface{}) {
				w.logger.Warn("WafPolicy deleted, reverting to defaults might be needed")
			},
		},
	)

	w.logger.Info("K8s WafPolicy watcher started")
	controller.Run(ctx.Done())
}
