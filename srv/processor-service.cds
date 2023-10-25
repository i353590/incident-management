using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService { 
    entity Incidents as projection on my.Incidents;

    @readonly
    entity Customers as projection on my.Customers;
}
extend projection ProcessorService.Customers with {
  firstName || ' ' || lastName as name: String
}
annotate ProcessorService.Incidents with @odata.draft.enabled;
annotate ProcessorService with @(requires: 'support');

annotate ProcessorService.Incidents with @changelog: {
  keys: [ customer.name, createdAt ]
} {
  title    @changelog;
  status   @changelog;
  customer @changelog: [ customer.name ];
};

annotate ProcessorService.Conversations with @changelog: {
  keys: [ author, timestamp ]
} {
  message  @changelog;
}